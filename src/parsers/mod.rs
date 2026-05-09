use std::{ffi::OsStr, path::Path};

mod game;
mod ip_filtering;
pub mod runtimes;

// Given a path, returns a function that will take the contents of that file and return the sanitized version.
pub fn get_file_sanitization_strategy(path: &Path) -> Option<fn(String) -> String> {
    let filename = path.file_name().and_then(OsStr::to_str)?;

    match filename {
        "game.log" => Some(game::process_game_log),

        // Runtime condensing is done in the runtimes.rs parser
        "runtime.log" => Some(runtimes::process_runtimes_log),

        // Pass through, but replace .txt with .log
        "asset.log"
        | "asset.log.json"
        | "atmos.html"
        | "attack.log.json"
        | "attack.log"
        | "botany.html"
        | "cargo.html"
        | "circuit.html"
        | "cloning.log.json"
        | "cloning.log"
        | "crafting.html"
        | "deaths.html"
        | "demo.log"
        | "dynamic.json"
        | "dynamic.log.json"
        | "dynamic.log"
        | "econ.log.json"
        | "econ.log"
        | "economy.log.json"
        | "economy.log"
        | "engine.html"
        | "experimentor.html"
        | "gravity.html"
        | "hallucinations.html"
        | "harddel.log.json"
        | "harddel.log"
        | "harddels.log.json"
        | "harddels.log"
        | "hypertorus.html"
        | "id_card_changes.html"
        | "init_profiler.json"
        | "init_times.json"
        | "initialize.log.json"
        | "initialize.log"
        | "job_debug.log.json"
        | "job_debug.log"
        | "kudzu.html"
        | "manifest.log.json"
        | "manifest.log"
        | "map_errors.log.json"
        | "map_errors.log"
        | "mecha.log.json"
        | "mecha.log"
        | "mob_tags.log.json"
        | "mob_tags.log"
        | "nanites.html"
        | "newscaster.json"
        | "overlay.log.json"
        | "overlay.log"
        | "paper.log.json"
        | "paper.log"
        | "pda.log.json"
        | "pda.log"
        | "portals.html"
        | "presents.html"
        | "profiler.json"
        | "qdel.log.json"
        | "qdel.log"
        | "radiation.html"
        | "records.html"
        | "research.html"
        | "round_end_data.html"
        | "round_end_data.json"
        | "sendmaps.json"
        | "shuttle.log.json"
        | "shuttle.log"
        | "signal.log.json"
        | "signal.log"
        | "signals.log.json"
        | "signals.log"
        | "silicon.log.json"
        | "silicon.log"
        | "silo.json"
        | "silo.log.json"
        | "silo.log"
        | "singulo.html"
        | "speech_indicators.log.json"
        | "speech_indicators.log"
        | "supermatter.html"
        | "target_zone_switch.json"
        | "telecomms.log.json"
        | "telecomms.log"
        | "telesci.html"
        | "tool.log.json"
        | "tool.log"
        | "tools.log.json"
        | "tools.log"
        | "uplink.log.json"
        | "uplink.log"
        | "virus.log.json"
        | "virus.log"
        | "wires.html" => Some(std::convert::identity),

        perf_filename if perf_filename.starts_with("perf-") => Some(std::convert::identity),

        profiler_file
            if path
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|pname| pname == "profiler")) =>
        {
            Some(std::convert::identity)
        }

        _ => None,
    }
}

// Separate so we can tracy it
#[tracing::instrument(skip_all)]
fn read_to_string(path: &Path) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}
