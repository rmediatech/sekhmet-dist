use sekhmet_store::SekhmetStore;

pub struct CliArgs {
    pub cmd: String,
    pub sub: Option<String>,
    pub cfg_path: Option<String>,
    pub db_override: Option<String>,
    pub bind_override: Option<String>,
    pub os_target: Option<String>,
    pub out_path: Option<String>,
    pub seed_hex: Option<String>,
    pub emergency: bool,
}

impl CliArgs {
    pub fn parse() -> Self {
        let args: Vec<String> = std::env::args().collect();
        let cmd = args.get(1).cloned().unwrap_or_else(|| "serve".to_string());
        let sub = args.get(2).and_then(|s| {
            if s.starts_with("--") {
                None
            } else {
                Some(s.clone())
            }
        });

        let mut cfg_path = None;
        let mut db_override = None;
        let mut bind_override = None;
        let mut os_target = None;
        let mut out_path = None;
        let mut seed_hex = None;
        let mut emergency = false;

        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--config" if i + 1 < args.len() => {
                    cfg_path = Some(args[i + 1].clone());
                    i += 2;
                }
                "--db" if i + 1 < args.len() => {
                    db_override = Some(args[i + 1].clone());
                    i += 2;
                }
                "--bind" if i + 1 < args.len() => {
                    bind_override = Some(args[i + 1].clone());
                    i += 2;
                }
                "--os" if i + 1 < args.len() => {
                    os_target = Some(args[i + 1].clone());
                    i += 2;
                }
                "--out" if i + 1 < args.len() => {
                    out_path = Some(args[i + 1].clone());
                    i += 2;
                }
                "--seed" if i + 1 < args.len() => {
                    seed_hex = Some(args[i + 1].clone());
                    i += 2;
                }
                "--emergency" => {
                    emergency = true;
                    i += 1;
                }
                _ => i += 1,
            }
        }

        Self {
            cmd,
            sub,
            cfg_path,
            db_override,
            bind_override,
            os_target,
            out_path,
            seed_hex,
            emergency,
        }
    }
}

pub fn execute_key_cmd(
    sub: Option<&str>,
    db_path: &str,
    seed_hex: Option<&str>,
    emergency: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = SekhmetStore::open(db_path)?;
    match sub.unwrap_or("status") {
        "rotate" => {
            let st = store.rotate_root_key(emergency)?;
            println!(
                "{{\"status\":\"rotated\",\"emergency\":{},\"primary_kid\":\"{}\",\"retiring_kid\":{:?}}}",
                emergency, st.primary_kid, st.retiring_kid
            );
        }
        "import" => {
            let seed = seed_hex.ok_or("Missing --seed <64-hex> for BYOK import")?;
            let st = store.import_byok_key(seed, emergency)?;
            println!(
                "{{\"status\":\"imported_byok\",\"emergency\":{},\"primary_kid\":\"{}\",\"retiring_kid\":{:?}}}",
                emergency, st.primary_kid, st.retiring_kid
            );
        }
        _ => {
            let kr = store.load_or_init_keyring(None)?;
            println!(
                "{{\"status\":\"ok\",\"primary_kid\":\"{}\",\"retiring_kid\":{:?}}}",
                kr.primary.key_id(),
                kr.retiring.as_ref().map(|r| r.key_id())
            );
        }
    }
    Ok(())
}

pub fn execute_service_cmd(
    sub: Option<&str>,
    os_target: Option<&str>,
    cfg_path: Option<&str>,
    db_path: String,
    bind_addr: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use sekhmet_service::{ServiceDescriptor, TargetOsPlatform};
    let platform = TargetOsPlatform::parse_or_detect(os_target)?;
    let config_path = cfg_path
        .unwrap_or("/var/lib/sekhmet/sekhmet.yaml")
        .to_string();
    let desc = ServiceDescriptor {
        binary_path: "/usr/local/bin/sekhmet".to_string(),
        working_dir: "/var/lib/sekhmet".to_string(),
        config_path,
        db_path,
        bind_addr,
    };
    match sub.unwrap_or("preview") {
        "install" => {
            let (target_path, manifest) = desc.render_manifest(platform)?;
            std::fs::write(&target_path, &manifest)?;
            println!("{{\"status\":\"installed\",\"path\":\"{}\"}}", target_path);
        }
        "uninstall" => {
            let (target_path, _) = desc.render_uninstall_manifest(platform)?;
            if std::path::Path::new(&target_path).exists() {
                std::fs::remove_file(&target_path)?;
            }
            println!("{{\"status\":\"uninstalled\",\"removed\":\"{}\"}}", target_path);
        }
        "preview-uninstall" => {
            let (target_path, script) = desc.render_uninstall_manifest(platform)?;
            println!("# Uninstall Target: {}\n{}", target_path, script);
        }
        "status" => {
            let (target_path, _) = desc.render_manifest(platform)?;
            let installed = std::path::Path::new(&target_path).exists();
            println!(
                "{{\"status\":\"ok\",\"installed\":{},\"path\":\"{}\"}}",
                installed, target_path
            );
        }
        _ => {
            let (target_path, manifest) = desc.render_manifest(platform)?;
            println!("# Target Path: {}\n{}", target_path, manifest);
        }
    }
    Ok(())
}

pub fn execute_heal_or_intel_cmd(
    cmd: &str,
    db_path: &str,
    grace_ttl_secs: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = SekhmetStore::open(db_path)?;
    if cmd == "intel" {
        let summary = store.get_intelligence_summary()?;
        println!("{}", serde_json::to_string(&summary)?);
    } else {
        let report = store.self_heal(grace_ttl_secs)?;
        println!("{}", serde_json::to_string(&report)?);
    }
    Ok(())
}

pub fn execute_non_serve_cmd(
    args: CliArgs,
    cfg: sekhmet_config::SekhmetSstConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    match args.cmd.as_str() {
        "config" => {
            if args.sub.as_deref() == Some("validate") {
                println!(
                    "{{\"status\":\"valid\",\"issuer\":\"{}\",\"bind\":\"{}\",\"db\":\"{}\"}}",
                    cfg.issuer, cfg.bind_addr, cfg.db_path
                );
            } else {
                let yaml = cfg.render_canonical_yaml();
                match args.out_path {
                    Some(p) => {
                        std::fs::write(&p, &yaml)?;
                        println!("{{\"status\":\"written\",\"path\":\"{}\"}}", p);
                    }
                    None => print!("{}", yaml),
                }
            }
        }
        "key" => execute_key_cmd(
            args.sub.as_deref(),
            &cfg.db_path,
            args.seed_hex.as_deref(),
            args.emergency,
        )?,
        "service" => execute_service_cmd(
            args.sub.as_deref(),
            args.os_target.as_deref(),
            args.cfg_path.as_deref(),
            cfg.db_path,
            cfg.bind_addr,
        )?,
        "heal" | "intel" => {
            execute_heal_or_intel_cmd(&args.cmd, &cfg.db_path, cfg.access_token_ttl_secs)?
        }
        "maintenance" => {
            let (pruned, entries, head) = SekhmetStore::open(&cfg.db_path)?.run_maintenance()?;
            println!(
                "{{\"status\":\"ok\",\"pruned_sessions\":{},\"merkle_entries\":{},\"head_hash\":\"{}\"}}",
                pruned, entries, head
            );
        }
        "audit" => {
            let (count, head) = SekhmetStore::open(&cfg.db_path)?.verify_merkle_chain()?;
            println!(
                "{{\"status\":\"verified\",\"entries\":{},\"head_hash\":\"{}\"}}",
                count, head
            );
        }
        _ => {
            eprintln!("Usage: sekhmet <serve|config|key|service|heal|intel|maintenance|audit> [--config <path>]");
            std::process::exit(1);
        }
    }
    Ok(())
}
