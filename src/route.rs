use std::{collections::HashMap, io::ErrorKind, path::PathBuf, sync::Arc};

use axum::{
    extract::{OriginalUri, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Serialize;

use crate::{app_state::AppState, parsers::get_file_sanitization_strategy};

pub const RUNTIME_CONDENSED_JSON: &str = "runtime.condensed.json";
pub const RUNTIME_CONDENSED_TXT: &str = "runtime.condensed.txt";

const NOT_FOUND: (StatusCode, &str) = (StatusCode::NOT_FOUND, "couldn't find that path");

#[derive(Serialize)]
struct TraversalItem {
    name: String,
    path: String,
    is_dir: bool,
}

#[tracing::instrument(skip(request_headers))]
pub async fn get(
    State(state): State<Arc<AppState>>,
    OriginalUri(uri): OriginalUri,
    Query(params): Query<HashMap<String, String>>,
    request_headers: HeaderMap,
) -> Result<impl IntoResponse, axum::response::Response> {
    let decoded_path = percent_encoding::percent_decode_str(uri.path()).decode_utf8_lossy();
    tracing::debug!("path after percent decoding: {}", decoded_path);
    let requested_path = state
        .config
        .raw_logs_path
        .join(decoded_path.strip_prefix('/').unwrap_or(&decoded_path));


    if !requested_path.starts_with(&state.config.raw_logs_path) {
        tracing::warn!("attempted path traversal: {uri}");
        return Ok((StatusCode::FORBIDDEN, "attempted path traversal").into_response());
    }

    match state.path_is_ongoing_round(&requested_path).await {
        Ok(true) => {
            tracing::debug!("blocking access to ongoing round");
            return Ok(NOT_FOUND.into_response());
        }

        Ok(false) => {}

        Err(error) => {
            return Ok(error_to_response(
                error,
                StatusCode::INTERNAL_SERVER_ERROR,
                "error figuring out if that round is ongoing or not",
            ));
        }
    }

    // Pretend files
    match requested_path.file_name().and_then(std::ffi::OsStr::to_str) {
        name @ Some(RUNTIME_CONDENSED_TXT) | name @ Some(RUNTIME_CONDENSED_JSON) => {
            let runtimes_file = requested_path.with_file_name("runtime.log");
            let runtimes_contents = std::fs::read_to_string(runtimes_file).map_err(|error| {
                error_to_response(error, StatusCode::NOT_FOUND, "couldn't find runtime.log")
            })?;

            if name == Some(RUNTIME_CONDENSED_TXT) {
                return Ok((
                    StatusCode::OK,
                    headers("text/plain"),
                    crate::parsers::runtimes::condense_runtimes_to_string(&runtimes_contents),
                )
                    .into_response());
            } else if name == Some(RUNTIME_CONDENSED_JSON) {
                return Ok((
                    StatusCode::OK,
                    headers("application/json"),
                    crate::parsers::runtimes::condense_runtimes_to_json(&runtimes_contents)
                        .to_string(),
                )
                    .into_response());
            } else {
                unreachable!();
            }
        }

        _ => {}
    }

    let metadata = tokio::fs::metadata(&requested_path)
        .await
        .map_err(|error| {
            if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) {
                NOT_FOUND.into_response()
            } else {
                error_to_response(
                    error,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "couldn't get metadata of path",
                )
            }
        })?;

    if metadata.is_dir() {
        if params.get("format").map(|v| v == "json").unwrap_or(false) {
            let items = collect_traversal_items(&state, &requested_path)
                .await
                .map_err(|error| {
                    error_to_response(
                        error,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "error creating traversal JSON",
                    )
                })?;
            Ok((
                StatusCode::OK,
                headers("application/json"),
                serde_json::to_string(&items).unwrap(),
            )
                .into_response())
        } else {
            Ok((
                StatusCode::OK,
                headers("text/html"),
                traversal_page(&state, &requested_path)
                    .await
                    .map_err(|error| {
                        error_to_response(
                            error,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "error creating traversal page",
                        )
                    }),
            )
                .into_response())
        }
    } else if metadata.is_file() {
        let Some(strategy) = get_file_sanitization_strategy(&requested_path) else {
            return Ok(NOT_FOUND.into_response());
        };

        let extension = requested_path
            .extension()
            .and_then(std::ffi::OsStr::to_str);

        let scrubbed = strategy(std::fs::read_to_string(&requested_path).map_err(|error| {
            error_to_response(
                error,
                StatusCode::INTERNAL_SERVER_ERROR,
                "couldn't read file",
            )
        })?);

        // Decide whether to wrap the file in the styled log viewer page.
        // Wrap only when:
        //   * the client did NOT pass ?raw=1
        //   * the client's Accept header includes text/html (i.e. a browser)
        //   * the file is plain text (.log, .txt, no extension), not JSON or
        //     a pre-rendered HTML round report.
        let force_raw = params.get("raw").map(|v| v == "1").unwrap_or(false);
        let prefers_html = !force_raw && accept_prefers_html(&request_headers);
        let plain_text_extension = matches!(extension, Some("log") | Some("txt") | None);

        if prefers_html && plain_text_extension {
            let relative = requested_path
                .strip_prefix(&state.config.raw_logs_path)
                .unwrap_or(&requested_path);
            return Ok((
                StatusCode::OK,
                headers("text/html; charset=utf-8"),
                viewer_page(relative, &scrubbed),
            )
                .into_response());
        }

        let content_type = match extension {
            Some("json") => "application/json",
            Some("html") => "text/html",
            _ => "text/plain; charset=utf-8",
        };
        Ok((StatusCode::OK, headers(content_type), scrubbed).into_response())
    } else {
        Ok((StatusCode::BAD_REQUEST, "tried to access weird file").into_response())
    }
}

async fn collect_traversal_items(
    state: &AppState,
    path: &std::path::Path,
) -> eyre::Result<Vec<TraversalItem>> {
    let mut items = vec![];

    let read_dir = std::fs::read_dir(path)?;

    for entry in read_dir {
        let entry = entry?;
        let entry_path = entry.path();

        if state.path_is_ongoing_round(&entry_path).await? {
            continue;
        }

        let file_type = entry.file_type()?;
        let is_dir = file_type.is_dir();

        // build path relative to raw_logs_path
        let link_path = match entry_path.strip_prefix(&state.config.raw_logs_path) {
            Ok(link_path) => link_path,
            Err(_) => eyre::bail!("couldn't strip prefix with raw logs path"),
        };

        if is_dir || get_file_sanitization_strategy(&entry_path).is_some() {
            items.push(TraversalItem {
                name: entry.file_name().to_string_lossy().into_owned(),
                path: format!("/{}", link_path.display()),
                is_dir,
            });

            // add fake runtime condensed links
            if !is_dir
                && entry_path
                    .file_stem()
                    .map(|s| s == "runtime")
                    .unwrap_or(false)
            {
                items.push(TraversalItem {
                    name: RUNTIME_CONDENSED_JSON.to_string(),
                    path: format!(
                        "/{}",
                        link_path.with_file_name(RUNTIME_CONDENSED_JSON).display()
                    ),
                    is_dir: false,
                });
                items.push(TraversalItem {
                    name: RUNTIME_CONDENSED_TXT.to_string(),
                    path: format!(
                        "/{}",
                        link_path.with_file_name(RUNTIME_CONDENSED_TXT).display()
                    ),
                    is_dir: false,
                });
            }
        }
    }

    items.sort_by(|a, b| (b.is_dir, &a.name).cmp(&(a.is_dir, &b.name)));

    Ok(items)
}

fn headers(content_type: &str) -> [(&'static str, &str); 2] {
    [
        ("cache-control", "public, max-age=31536000"),
        ("content-type", content_type),
    ]
}

fn error_to_response(
    error: impl std::fmt::Debug,
    status_code: StatusCode,
    message: &'static str,
) -> axum::response::Response {
    tracing::error!("{message}: {error:?}");
    (
        status_code,
        format!(
            "{message}\nplease report this error to mothblocks, ideally with the url you tried"
        ),
    )
        .into_response()
}

/// Shared "ntOS95" / Windows-95-PDA chrome used by both the traversal
/// listing and the file viewer page. Mirrors the design tokens from
/// the upstream tgstation tgui-core ntOS95 theme:
///   * teal desktop background (`#008080`)
///   * medium-gray window chrome (`#bfbfbf`) with 3D outset bevel
///   * navy title bar (`#000080`) with white "MS Sans Serif" text
///   * sunken white content area for actual data
///   * sharp corners and zero transitions
///
/// Source reference: https://github.com/tgstation/tgui-core/blob/main/styles/themes/ntOS95.scss
const RETRO_CSS: &str = "
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: \"MS Sans Serif\", \"Microsoft Sans Serif\", Tahoma, sans-serif;
    font-size: 11px;
    background: #008080;
    color: #000;
    min-height: 100vh;
    padding: 1.5rem;
}
.window {
    max-width: 960px;
    margin: 0 auto;
    background: #bfbfbf;
    border-top: 2px solid #ffffff;
    border-left: 2px solid #ffffff;
    border-right: 2px solid #404040;
    border-bottom: 2px solid #404040;
    box-shadow: 1px 1px 0 0 #000;
    padding: 2px;
}
.title-bar {
    background: #000080;
    color: #fff;
    padding: 3px 4px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-weight: bold;
    user-select: none;
}
.title-bar .path { display: flex; align-items: center; gap: 4px; overflow: hidden; }
.title-bar .path a { color: #fff; text-decoration: none; }
.title-bar .path a:hover { text-decoration: underline; }
.title-bar .controls { display: flex; gap: 2px; flex-shrink: 0; }
.title-bar .controls .btn {
    width: 18px; height: 16px;
    background: #bfbfbf;
    color: #000;
    border-top: 1px solid #ffffff;
    border-left: 1px solid #ffffff;
    border-right: 1px solid #404040;
    border-bottom: 1px solid #404040;
    font-family: \"Marlett\", monospace;
    font-size: 9px;
    line-height: 14px;
    text-align: center;
    cursor: default;
}
.menu-bar {
    background: #bfbfbf;
    padding: 2px 4px;
    border-bottom: 1px solid #808080;
    font-size: 11px;
    color: #000;
    display: flex;
    justify-content: space-between;
    gap: 1rem;
}
.menu-bar .summary { color: #000; }
.content {
    background: #ffffff;
    color: #000;
    border-top: 1px solid #404040;
    border-left: 1px solid #404040;
    border-right: 1px solid #ffffff;
    border-bottom: 1px solid #ffffff;
    margin: 4px;
    padding: 4px;
    font-family: \"Lucida Console\", \"Courier New\", Courier, monospace;
    font-size: 12px;
    line-height: 1.4;
}
.empty {
    padding: 2rem;
    text-align: center;
    color: #808080;
}
ul.listing {
    list-style: none;
}
.item a {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 2px 4px;
    color: #000080;
    text-decoration: none;
    font-family: \"MS Sans Serif\", Tahoma, sans-serif;
    font-size: 11px;
}
.item a:hover { background: #000080; color: #ffffff; }
.item .icon {
    display: inline-block;
    width: 16px;
    text-align: center;
    flex-shrink: 0;
}
.item.dir  .icon::before { content: \"\\1F4C1\"; }  /* folder emoji */
.item.file .icon::before { content: \"\\1F4C4\"; }  /* page emoji */
.status-bar {
    background: #bfbfbf;
    padding: 3px 6px;
    border-top: 1px solid #ffffff;
    font-size: 11px;
    color: #000;
    border-top: 1px solid #ffffff;
    margin-top: 2px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
pre {
    font-family: \"Lucida Console\", \"Courier New\", Courier, monospace;
    font-size: 12px;
    line-height: 1.4;
    white-space: pre;
    overflow-x: auto;
    background: #ffffff;
    color: #000;
    padding: 4px 6px;
    margin: 0;
}
/* Per-line colour coding by log category. Tuned for readability
   against the white console background, mostly retaining the original
   palette's intent but with darker shades that contrast properly. */
.log-attack        { color: #c0392b; }
.log-say           { color: #1b5e57; }
.log-emote         { color: #1b5e57; font-style: italic; }
.log-dead          { color: #6a1b9a; font-style: italic; }
.log-ooc           { color: #1565c0; }
.log-admin         { color: #1565c0; font-weight: 600; }
.log-adminprivate  { color: #607d8b; font-style: italic; }
.log-access        { color: #455a64; }
.log-event         { color: #b9770e; }
.log-chat          { color: #00695c; }
.log-mechanism     { color: #6d4c41; }
.log-econ          { color: #2e6b35; }
.log-system        { color: #555; }
.log-censored      { color: #aaaaaa; font-style: italic; }
";

async fn traversal_page(state: &AppState, path: &std::path::Path) -> eyre::Result<String> {
    let items = collect_traversal_items(state, path).await?;

    let list_html: String = items
        .iter()
        .map(|item| {
            // Each item carries dir/file class so the stylesheet picks
            // the right Win95 icon glyph for it.
            if item.is_dir {
                format!(
                    "<li class=\"item dir\"><a href='{path}'><span class=\"icon\"></span>{name}/</a></li>",
                    path = item.path,
                    name = html_escape(&item.name),
                )
            } else {
                format!(
                    "<li class=\"item file\"><a href='{path}'><span class=\"icon\"></span>{name}</a></li>",
                    path = item.path,
                    name = html_escape(&item.name),
                )
            }
        })
        .collect();

    let relative_to_top = path.strip_prefix(&state.config.raw_logs_path)?;
    let title = relative_to_top.display().to_string();
    let display_title = if title.is_empty() { String::from("Logs") } else { title.clone() };
    let breadcrumbs = link_segments(relative_to_top);
    let item_count = items.len();
    let item_word = if item_count == 1 { "object" } else { "objects" };
    let body = if items.is_empty() {
        String::from("<div class=\"empty\">No log files in this directory.</div>")
    } else {
        format!("<ul class=\"listing\">{list_html}</ul>")
    };

    Ok(format!(
        "<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<title>{display_title}</title>
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
<style>{RETRO_CSS}</style>
</head>
<body>
<div class=\"window\">
  <div class=\"title-bar\">
    <div class=\"path\">{breadcrumbs}</div>
    <div class=\"controls\"><div class=\"btn\">_</div><div class=\"btn\">\u{25A1}</div><div class=\"btn\">x</div></div>
  </div>
  <div class=\"menu-bar\">
    <div>File &nbsp; Edit &nbsp; View &nbsp; Help</div>
    <div class=\"summary\">{item_count} {item_word}</div>
  </div>
  <div class=\"content\">{body}</div>
  <div class=\"status-bar\"><div>Ready</div><div>{item_count} {item_word}</div></div>
</div>
</body>
</html>"
    ))
}

fn accept_prefers_html(headers: &HeaderMap) -> bool {
    headers
        .get("accept")
        .and_then(|h| h.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false)
}

fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Pick a CSS class name based on the log category in this line.
/// Lines look like `[2026-04-30 16:20:42.301] CATEGORY: rest of line`.
/// Categories may be prefixed with `GAME-`. Lines that don't match the
/// shape (e.g. `Starting up round ID 2.`, parser-generated `-censored(...)-`,
/// continuation lines) get a default or censored class.
fn line_class(line: &str) -> &'static str {
    if line.starts_with("-censored(") {
        return "log-censored";
    }
    let Some(rest) = line.strip_prefix('[') else {
        return "log-default";
    };
    let Some((_, after_bracket)) = rest.split_once(']') else {
        return "log-default";
    };
    let after = after_bracket.trim_start();
    let Some((category_with_colon, _)) = after.split_once(' ') else {
        return "log-default";
    };
    let Some(category) = category_with_colon.strip_suffix(':') else {
        return "log-default";
    };
    // Strip the optional GAME- prefix the parser leaves alone (e.g. GAME-SAY).
    match category.trim_start_matches("GAME-") {
        "ATTACK" | "VICTIM" => "log-attack",
        "SAY" | "WHISPER" | "RADIO" => "log-say",
        "EMOTE" | "RADIO_EMOTE" | "SPEECH_INDICATORS" => "log-emote",
        "DSAY" | "DEAD" => "log-dead",
        "OOC" => "log-ooc",
        "ADMIN" | "ASAY" => "log-admin",
        "ADMINPRIVATE" => "log-adminprivate",
        "ACCESS" => "log-access",
        "PRAY" | "VOTE" | "GAME" => "log-event",
        "PDA" | "CHAT" | "COMMENT" | "TELECOMMS" => "log-chat",
        "MECHA" | "SHUTTLE" | "TRANSPORT" => "log-mechanism",
        "ECON" | "ECONOMY" | "OWNERSHIP" => "log-econ",
        "TOPIC" | "SQL" => "log-system",
        _ => "log-default",
    }
}

fn colorize_line(line: &str) -> String {
    let class = line_class(line);
    if class == "log-default" {
        // No wrapping needed for the default class; saves bytes on long files.
        html_escape(line)
    } else {
        format!("<span class=\"{class}\">{}</span>", html_escape(line))
    }
}

fn viewer_page(relative_path: &std::path::Path, scrubbed_content: &str) -> String {
    let title = relative_path.display().to_string();
    let breadcrumbs = link_segments(relative_path);
    // Per-line colourisation by log category. Each line is HTML-escaped and
    // wrapped in a span with a category-specific class so the stylesheet can
    // tint ATTACK red, SAY green, ADMIN blue, etc.
    let body: String = scrubbed_content
        .lines()
        .map(colorize_line)
        .collect::<Vec<_>>()
        .join("\n");
    let line_count = scrubbed_content.lines().count();
    let line_word = if line_count == 1 { "line" } else { "lines" };

    format!(
        "<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<title>{title}</title>
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
<style>{RETRO_CSS}
.menu-bar a {{ color: #000080; text-decoration: none; padding: 0 4px; }}
.menu-bar a:hover {{ background: #000080; color: #fff; }}
</style>
</head>
<body>
<div class=\"window\">
  <div class=\"title-bar\">
    <div class=\"path\">{breadcrumbs}</div>
    <div class=\"controls\"><div class=\"btn\">_</div><div class=\"btn\">\u{25A1}</div><div class=\"btn\">x</div></div>
  </div>
  <div class=\"menu-bar\">
    <div>File &nbsp; Edit &nbsp; View &nbsp; <a href=\"?raw=1\">Raw</a></div>
    <div class=\"summary\">{line_count} {line_word}</div>
  </div>
  <div class=\"content\"><pre>{body}</pre></div>
  <div class=\"status-bar\"><div>Ready</div><div>{line_count} {line_word}</div></div>
</div>
</body>
</html>"
    )
}

fn link_segments(path: &std::path::Path) -> String {
    let mut pieces = Vec::new();

    let mut path_to_this_point = PathBuf::new();
    for component in path.components() {
        path_to_this_point = path_to_this_point.join(component);
        pieces.push(format!(
            "<a href='/{}'>{}</a>",
            path_to_this_point.display(),
            component.as_os_str().to_string_lossy()
        ));
    }

    pieces.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accept_header(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("accept", value.parse().unwrap());
        h
    }

    #[test]
    fn accept_prefers_html_browser_default() {
        // Firefox/Chrome default Accept header
        let h = accept_header(
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        );
        assert!(accept_prefers_html(&h));
    }

    #[test]
    fn accept_prefers_html_curl_default() {
        // curl sends Accept: */*
        let h = accept_header("*/*");
        assert!(!accept_prefers_html(&h));
    }

    #[test]
    fn accept_prefers_html_no_header() {
        let h = HeaderMap::new();
        assert!(!accept_prefers_html(&h));
    }

    #[test]
    fn accept_prefers_html_explicit_text_plain() {
        let h = accept_header("text/plain");
        assert!(!accept_prefers_html(&h));
    }

    #[test]
    fn html_escape_handles_special_chars() {
        assert_eq!(
            html_escape(r#"<script>alert("x")</script>"#),
            "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"
        );
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("it's"), "it&#39;s");
    }

    #[test]
    fn viewer_page_contains_path_and_escaped_body() {
        let path = std::path::Path::new("2026/04/30/round-2/game.log");
        let content = "[2026-04-30 16:20:42.301] GAME: <not really a tag>";
        let html = viewer_page(path, content);
        assert!(html.contains("<title>2026/04/30/round-2/game.log</title>"));
        assert!(html.contains("&lt;not really a tag&gt;"));
        assert!(html.contains("?raw=1"));
        // breadcrumb segment for round-2
        assert!(html.contains(">round-2</a>"));
    }

    #[test]
    fn line_class_matches_categories() {
        let cases = &[
            ("[2026-04-30 16:20:42.301] ATTACK: ckey hit", "log-attack"),
            ("[2026-04-30 16:20:42.301] GAME-ATTACK: ckey hit", "log-attack"),
            ("[2026-04-30 16:20:42.301] SAY: ckey says", "log-say"),
            ("[2026-04-30 16:20:42.301] WHISPER: ckey whispers", "log-say"),
            ("[2026-04-30 16:20:42.301] EMOTE: ckey emotes", "log-emote"),
            ("[2026-04-30 16:20:42.301] DSAY: ghost talks", "log-dead"),
            ("[2026-04-30 16:20:42.301] OOC: out of character", "log-ooc"),
            ("[2026-04-30 16:20:42.301] ADMIN: ckey adminned", "log-admin"),
            ("[2026-04-30 16:20:42.301] ASAY: admin chat", "log-admin"),
            ("[2026-04-30 16:20:42.301] ADMINPRIVATE: hidden", "log-adminprivate"),
            ("[2026-04-30 16:20:42.301] ACCESS: Login: ckey", "log-access"),
            ("[2026-04-30 16:20:42.301] PRAY: dear god", "log-event"),
            ("[2026-04-30 16:20:42.301] VOTE: ckey votes", "log-event"),
            ("[2026-04-30 16:20:42.301] GAME: round started", "log-event"),
            ("[2026-04-30 16:20:42.301] PDA: ping", "log-chat"),
            ("[2026-04-30 16:20:42.301] TELECOMMS: chatter", "log-chat"),
            ("[2026-04-30 16:20:42.301] MECHA: hello", "log-mechanism"),
            ("[2026-04-30 16:20:42.301] SHUTTLE: dock", "log-mechanism"),
            ("[2026-04-30 16:20:42.301] ECON: 100cr", "log-econ"),
            ("[2026-04-30 16:20:42.301] TOPIC: probe", "log-system"),
            ("[2026-04-30 16:20:42.301] SQL: query", "log-system"),
            ("-censored(empty_line)-", "log-censored"),
            ("-censored(access detail)-", "log-censored"),
            ("Not a log-shaped line at all", "log-default"),
            ("[2026-04-30 16:20:42.301] UNKNOWN_TAG: stuff", "log-default"),
        ];
        for (line, expected) in cases {
            assert_eq!(line_class(line), *expected, "line: {line}");
        }
    }

    #[test]
    fn colorize_line_wraps_categorized_lines_only() {
        // Default lines pass through with no span wrapper to save bytes.
        let plain = colorize_line("Not a log line");
        assert_eq!(plain, "Not a log line");

        let attack = colorize_line("[2026-04-30 16:20:42.301] ATTACK: ckey hit target");
        assert!(attack.starts_with("<span class=\"log-attack\">"));
        assert!(attack.ends_with("</span>"));
        // Body is HTML-escaped inside the span.
        assert!(attack.contains("ATTACK:"));
    }

    #[test]
    fn viewer_page_colorizes_attack_line() {
        let path = std::path::Path::new("round-1/game.log");
        let content = "[2026-04-30 16:20:42.301] ATTACK: ckey hit target";
        let html = viewer_page(path, content);
        assert!(html.contains("<span class=\"log-attack\">"));
        assert!(html.contains(".log-attack"));
    }
}
