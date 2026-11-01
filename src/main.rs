mod cli;

use cli::{execute_non_serve_cmd, CliArgs};
use sekhmet::{build_sekhmet_router, SekhmetAppState};
use sekhmet_config::SekhmetSstConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = CliArgs::parse();
    let mut cfg = match args.cfg_path {
        Some(ref p) => SekhmetSstConfig::load_from_file(p)?,
        None => SekhmetSstConfig::default(),
    };
    if let Some(ref db) = args.db_override {
        cfg.db_path = db.clone();
    }
    if let Some(ref bind) = args.bind_override {
        cfg.bind_addr = bind.clone();
    }

    if args.cmd == "serve" {
        let (bind_addr, db_path) = (cfg.bind_addr.clone(), cfg.db_path.clone());
        let state = SekhmetAppState::from_config(cfg)?;
        state.spawn_autonomous_self_healing_pulse();
        let app = build_sekhmet_router(state);
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        println!(
            "{{\"status\":\"listening\",\"engine\":\"sekhmet\",\"bind\":\"{}\",\"db\":\"{}\"}}",
            bind_addr, db_path
        );
        axum::serve(listener, app).await?;
        return Ok(());
    }

    execute_non_serve_cmd(args, cfg)
}
