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

async fn traversal_page(state: &AppState, path: &std::path::Path) -> eyre::Result<String> {
    let items = collect_traversal_items(state, path).await?;

    let list_html: String = items
        .iter()
        .map(|item| {
            if item.is_dir {
                format!(
                    "<li><a href='{path}'>{name}/</a></li>",
                    path = item.path,
                    name = item.name
                )
            } else {
                format!(
                    "<li><a href='{path}'>{name}</a></li>",
                    path = item.path,
                    name = item.name
                )
            }
        })
        .collect();

    let relative_to_top = path.strip_prefix(&state.config.raw_logs_path)?;

    Ok(format!(
        "<html>
            <head>
                <title>{}</title>
            </head>
            <body>
                <p>{}</p>
                <hr />
                <ul>{}</ul>
            </body>
        </html>",
        relative_to_top.display(),
        link_segments(relative_to_top),
        list_html
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

fn viewer_page(relative_path: &std::path::Path, scrubbed_content: &str) -> String {
    let title = relative_path.display().to_string();
    let breadcrumbs = link_segments(relative_path);
    let body = html_escape(scrubbed_content);

    format!(
        "<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<title>{title}</title>
<meta name=\"color-scheme\" content=\"light dark\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: Inter, system-ui, -apple-system, Segoe UI, sans-serif;
    background: light-dark(#f3f6f7, #1c1d1f);
    color: light-dark(#222, #ddd);
    min-height: 100vh;
}}
header {{
    padding: 1rem 1.5rem;
    background: light-dark(#fff, #2a2c2f);
    border-bottom: 1px solid light-dark(#e0e4e7, #3a3c3f);
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
    position: sticky;
    top: 0;
    z-index: 10;
}}
.path {{ font-size: 1.05rem; }}
.path a {{ color: inherit; text-decoration: none; }}
.path a:hover {{ text-decoration: underline; }}
.actions {{ font-size: 0.9rem; }}
.actions a {{
    color: light-dark(#0066cc, #66aaff);
    text-decoration: none;
    padding: 0.35rem 0.7rem;
    border-radius: 4px;
    background: light-dark(#eef3f9, #353739);
}}
.actions a:hover {{ background: light-dark(#dbe7f3, #424446); }}
pre {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.85rem;
    padding: 1.5rem;
    line-height: 1.45;
    white-space: pre;
    overflow-x: auto;
    background: light-dark(#fff, #1c1d1f);
}}
</style>
</head>
<body>
<header>
<div class=\"path\">{breadcrumbs}</div>
<div class=\"actions\"><a href=\"?raw=1\">view raw</a></div>
</header>
<pre>{body}</pre>
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
        let content = "[ts] GAME: <not really a tag>";
        let html = viewer_page(path, content);
        assert!(html.contains("<title>2026/04/30/round-2/game.log</title>"));
        assert!(html.contains("&lt;not really a tag&gt;"));
        assert!(html.contains("?raw=1"));
        // breadcrumb segment for round-2
        assert!(html.contains(">round-2</a>"));
    }
}
