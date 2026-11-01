use sekhmet_crypto::{
    rfc6238_totp_at, verify_password_equalized, SekhmetClaims, SekhmetEd25519Signer,
};
use sekhmet_service::{ServiceDescriptor, TargetOsPlatform};

#[test]
fn test_rfc6238_official_ietf_test_vectors() {
    // Official IETF RFC 6238 Appendix B ASCII seed: "12345678901234567890"
    let secret = b"12345678901234567890";
    let vectors: &[(u64, &str)] = &[
        (59, "287082"),
        (1_111_111_109, "081804"),
        (1_111_111_111, "050471"),
        (1_234_567_890, "005924"),
        (2_000_000_000, "279037"),
        (20_000_000_000, "353130"),
    ];

    for &(timestamp, expected_6digit) in vectors {
        let actual = rfc6238_totp_at(secret, timestamp, 30);
        assert_eq!(
            actual, expected_6digit,
            "RFC 6238 TOTP mismatch at timestamp {}",
            timestamp
        );
    }
}

#[test]
fn test_rfc8032_ed25519_and_rfc7517_jwks_parity() {
    let seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    let signer = SekhmetEd25519Signer::from_seed_hex(seed_hex).expect("valid RFC 8032 seed");
    let jwks = signer.jwks_json();
    let key_obj = &jwks["keys"][0];
    assert_eq!(key_obj["kty"], "OKP");
    assert_eq!(key_obj["crv"], "Ed25519");
    assert_eq!(key_obj["alg"], "EdDSA");
    // RFC 8032 Test Vector 1 public key is d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
    // In Base64URL (no pad), that is "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    assert_eq!(
        key_obj["x"],
        "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    );

    let claims = SekhmetClaims {
        iss: "sekhmet.rmediatech.sovereign".to_string(),
        sub: "usr_rfc8032".to_string(),
        tid: "ten_rfc".to_string(),
        role: "owner".to_string(),
        jti: "jti_test_01".to_string(),
        iat: 1_700_000_000,
        exp: 1_700_003_600,
    };
    let token = signer.sign_jwt(&claims).unwrap();
    let verified = signer.verify_jwt(&token, 1_700_000_100).unwrap();
    assert_eq!(verified, claims);
}

#[test]
fn test_cross_os_service_manifest_parity() {
    let desc = ServiceDescriptor {
        binary_path: "/usr/local/bin/sekhmet".to_string(),
        working_dir: "/var/lib/sekhmet".to_string(),
        config_path: "/var/lib/sekhmet/sekhmet.yaml".to_string(),
        db_path: "/var/lib/sekhmet/sekhmet.db".to_string(),
        bind_addr: "127.0.0.1:4410".to_string(),
    };

    let (systemd_path, systemd_unit) = desc
        .render_manifest(TargetOsPlatform::LinuxSystemd)
        .unwrap();
    assert_eq!(systemd_path, "/etc/systemd/system/sekhmet.service");
    assert!(systemd_unit.contains("--config /var/lib/sekhmet/sekhmet.yaml"));
    assert!(systemd_unit.contains("NoNewPrivileges=yes"));
    assert!(systemd_unit.contains("ProtectSystem=strict"));

    let (openrc_path, openrc_script) = desc
        .render_manifest(TargetOsPlatform::LinuxOpenRc)
        .unwrap();
    assert_eq!(openrc_path, "/etc/init.d/sekhmet");
    assert!(openrc_script.contains("#!/sbin/openrc-run"));

    let (bsd_path, bsd_script) = desc.render_manifest(TargetOsPlatform::FreeBsdRc).unwrap();
    assert_eq!(bsd_path, "/usr/local/etc/rc.d/sekhmet");
    assert!(bsd_script.contains(". /etc/rc.subr"));

    let (win_path, win_script) = desc.render_manifest(TargetOsPlatform::WindowsScm).unwrap();
    assert!(win_path.ends_with("install_service.ps1"));
    assert!(win_script.contains("sc.exe create SekhmetAuth"));

    let (mac_path, mac_plist) = desc
        .render_manifest(TargetOsPlatform::MacOsLaunchd)
        .unwrap();
    assert_eq!(
        mac_path,
        "/Library/LaunchDaemons/com.rmediatech.sekhmet.plist"
    );
    assert!(mac_plist.contains("<string>com.rmediatech.sekhmet</string>"));

    // Verify uninstall manifests for all 5 OS platforms
    for platform in [
        TargetOsPlatform::LinuxSystemd,
        TargetOsPlatform::LinuxOpenRc,
        TargetOsPlatform::FreeBsdRc,
        TargetOsPlatform::WindowsScm,
        TargetOsPlatform::MacOsLaunchd,
    ] {
        let (u_path, u_script) = desc.render_uninstall_manifest(platform).unwrap();
        assert!(!u_path.is_empty());
        assert!(u_script.contains("sekhmet") || u_script.contains("SekhmetAuth"));
    }
}

#[test]
fn test_argon2id_dummy_equalizer_executes_without_panic() {
    assert!(!verify_password_equalized(None, "nonexistent-user-attempt"));
}

#[test]
fn test_zero_config_sqlite_keystore_persists_ed25519_across_reboots() {
    let tmp_db = "/tmp/sekhmet_keystore_reboot_test.db";
    let _ = std::fs::remove_file(tmp_db);

    let store1 = sekhmet_store::SekhmetStore::open(tmp_db).unwrap();
    let ring1 = store1.load_or_init_keyring(None).unwrap();
    let kid1 = ring1.primary.key_id().to_string();
    let jwks1 = ring1.jwks_json();
    drop(store1);

    // Simulate daemon restart on the same SQLite WAL database with zero config seed
    let store2 = sekhmet_store::SekhmetStore::open(tmp_db).unwrap();
    let ring2 = store2.load_or_init_keyring(None).unwrap();
    assert_eq!(ring2.primary.key_id(), kid1);
    assert_eq!(ring2.jwks_json(), jwks1);

    let _ = std::fs::remove_file(tmp_db);
    let _ = std::fs::remove_file(format!("{}-wal", tmp_db));
    let _ = std::fs::remove_file(format!("{}-shm", tmp_db));
}

#[test]
fn test_byok_seed_entropy_guard_rejects_weak_seeds() {
    use sekhmet_crypto::validate_ed25519_seed_entropy;

    // Reject all-zero seed
    assert!(validate_ed25519_seed_entropy(&"0".repeat(64)).is_err());
    // Reject repeating single-byte seed
    assert!(validate_ed25519_seed_entropy(&"aa".repeat(32)).is_err());
    // Reject low-entropy pattern
    assert!(validate_ed25519_seed_entropy(&"01020304".repeat(8)).is_err());
    // Accept high-entropy RFC 8032 seed
    assert!(validate_ed25519_seed_entropy(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    .is_ok());
}
