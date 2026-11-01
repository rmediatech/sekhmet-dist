use sekhmet_sanitize::{validate_safe_os_path, SekhmetSanitizeError};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SekhmetServiceError {
    #[error("Unsafe binary, config, or working directory path: {0}")]
    UnsafePath(#[from] SekhmetSanitizeError),
    #[error("Invalid listen address format.")]
    InvalidBindAddr,
    #[error("Unsupported OS service target: {0}")]
    UnsupportedTarget(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetOsPlatform {
    LinuxSystemd,
    LinuxOpenRc,
    FreeBsdRc,
    WindowsScm,
    MacOsLaunchd,
}

impl TargetOsPlatform {
    pub fn parse_or_detect(raw: Option<&str>) -> Result<Self, SekhmetServiceError> {
        match raw.map(|s| s.trim().to_ascii_lowercase()) {
            Some(ref s) if s == "systemd" || s == "linux" => Ok(Self::LinuxSystemd),
            Some(ref s) if s == "openrc" || s == "alpine" => Ok(Self::LinuxOpenRc),
            Some(ref s) if s == "freebsd" || s == "bsd" => Ok(Self::FreeBsdRc),
            Some(ref s) if s == "windows" || s == "win32" || s == "scm" => Ok(Self::WindowsScm),
            Some(ref s) if s == "macos" || s == "launchd" || s == "darwin" => {
                Ok(Self::MacOsLaunchd)
            }
            Some(other) => Err(SekhmetServiceError::UnsupportedTarget(other)),
            None => Ok(Self::detect_host()),
        }
    }

    pub fn detect_host() -> Self {
        if cfg!(target_os = "windows") {
            Self::WindowsScm
        } else if cfg!(target_os = "macos") {
            Self::MacOsLaunchd
        } else if cfg!(target_os = "freebsd") || cfg!(target_os = "openbsd") {
            Self::FreeBsdRc
        } else if Path::new("/sbin/openrc-run").exists() {
            Self::LinuxOpenRc
        } else {
            Self::LinuxSystemd
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServiceDescriptor {
    pub binary_path: String,
    pub working_dir: String,
    pub config_path: String,
    pub db_path: String,
    pub bind_addr: String,
}

impl ServiceDescriptor {
    pub fn validate(&self) -> Result<(), SekhmetServiceError> {
        validate_safe_os_path(&self.binary_path)?;
        validate_safe_os_path(&self.working_dir)?;
        validate_safe_os_path(&self.config_path)?;
        validate_safe_os_path(&self.db_path)?;
        if self.bind_addr.is_empty()
            || self.bind_addr.len() > 64
            || self
                .bind_addr
                .bytes()
                .any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'-' | b'[' | b']')))
        {
            return Err(SekhmetServiceError::InvalidBindAddr);
        }
        Ok(())
    }

    pub fn render_manifest(
        &self,
        platform: TargetOsPlatform,
    ) -> Result<(String, String), SekhmetServiceError> {
        self.validate()?;
        match platform {
            TargetOsPlatform::LinuxSystemd => {
                let path = "/etc/systemd/system/sekhmet.service".to_string();
                let unit = format!(
                    "[Unit]\n\
                     Description=Sekhmet Sovereign Auth & Identity Engine\n\
                     After=network-online.target\n\
                     Wants=network-online.target\n\
                     \n\
                     [Service]\n\
                     Type=simple\n\
                     WorkingDirectory={}\n\
                     ExecStart={} serve --config {} --db {} --bind {}\n\
                     Restart=always\n\
                     RestartSec=2\n\
                     NoNewPrivileges=yes\n\
                     ProtectSystem=strict\n\
                     ProtectHome=read-only\n\
                     PrivateTmp=yes\n\
                     ReadWritePaths={}\n\
                     \n\
                     [Install]\n\
                     WantedBy=multi-user.target\n",
                    self.working_dir,
                    self.binary_path,
                    self.config_path,
                    self.db_path,
                    self.bind_addr,
                    self.working_dir
                );
                Ok((path, unit))
            }
            TargetOsPlatform::LinuxOpenRc => {
                let path = "/etc/init.d/sekhmet".to_string();
                let script = format!(
                    "#!/sbin/openrc-run\n\
                     name=\"sekhmet\"\n\
                     description=\"Sekhmet Sovereign Auth & Identity Engine\"\n\
                     command=\"{}\"\n\
                     command_args=\"serve --config {} --db {} --bind {}\"\n\
                     command_background=true\n\
                     pidfile=\"/run/${{RC_SVCNAME}}.pid\"\n\
                     directory=\"{}\"\n",
                    self.binary_path,
                    self.config_path,
                    self.db_path,
                    self.bind_addr,
                    self.working_dir
                );
                Ok((path, script))
            }
            TargetOsPlatform::FreeBsdRc => {
                let path = "/usr/local/etc/rc.d/sekhmet".to_string();
                let script = format!(
                    "#!/bin/sh\n\
                     # PROVIDE: sekhmet\n\
                     # REQUIRE: DAEMON NETWORKING\n\
                     . /etc/rc.subr\n\
                     name=\"sekhmet\"\n\
                     rcvar=\"sekhmet_enable\"\n\
                     command=\"{}\"\n\
                     command_args=\"serve --config {} --db {} --bind {} &\"\n\
                     load_rc_config $name\n\
                     run_rc_command \"$1\"\n",
                    self.binary_path, self.config_path, self.db_path, self.bind_addr
                );
                Ok((path, script))
            }
            TargetOsPlatform::WindowsScm => {
                let path = "C:\\ProgramData\\Sekhmet\\install_service.ps1".to_string();
                let script = format!(
                    "# Windows Service Control Manager (SCM) Registration for Sekhmet\n\
                     $ErrorActionPreference = 'Stop'\n\
                     sc.exe create SekhmetAuth binPath= \"`\"{}\"`\" serve --config `\"{}\"`\" --db `\"{}\"`\" --bind {}\" start= auto DisplayName= \"Sekhmet Sovereign Auth Engine\"\n\
                     sc.exe description SekhmetAuth \"Sovereign Universal Auth, Ed25519 JWT & API Key Custody Daemon\"\n\
                     sc.exe failure SekhmetAuth reset= 60 actions= restart/2000/restart/2000/restart/2000\n\
                     sc.exe start SekhmetAuth\n",
                    self.binary_path, self.config_path, self.db_path, self.bind_addr
                );
                Ok((path, script))
            }
            TargetOsPlatform::MacOsLaunchd => {
                let path = "/Library/LaunchDaemons/com.rmediatech.sekhmet.plist".to_string();
                let plist = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                     <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                     <plist version=\"1.0\">\n\
                     <dict>\n\
                       <key>Label</key><string>com.rmediatech.sekhmet</string>\n\
                       <key>WorkingDirectory</key><string>{}</string>\n\
                       <key>ProgramArguments</key>\n\
                       <array>\n\
                         <string>{}</string>\n\
                         <string>serve</string>\n\
                         <string>--config</string><string>{}</string>\n\
                         <string>--db</string><string>{}</string>\n\
                         <string>--bind</string><string>{}</string>\n\
                       </array>\n\
                       <key>KeepAlive</key><true/>\n\
                       <key>RunAtLoad</key><true/>\n\
                     </dict>\n\
                     </plist>\n",
                    self.working_dir,
                    self.binary_path,
                    self.config_path,
                    self.db_path,
                    self.bind_addr
                );
                Ok((path, plist))
            }
        }
    }

    /// Generates the native OS service teardown/uninstall manifest & target file path for all 5 OS platforms.
    pub fn render_uninstall_manifest(
        &self,
        platform: TargetOsPlatform,
    ) -> Result<(String, String), SekhmetServiceError> {
        self.validate()?;
        match platform {
            TargetOsPlatform::LinuxSystemd => {
                let path = "/etc/systemd/system/sekhmet.service".to_string();
                let script = "#!/bin/sh\n\
                    set -e\n\
                    systemctl stop sekhmet.service 2>/dev/null || true\n\
                    systemctl disable sekhmet.service 2>/dev/null || true\n\
                    rm -f /etc/systemd/system/sekhmet.service\n\
                    systemctl daemon-reload\n"
                    .to_string();
                Ok((path, script))
            }
            TargetOsPlatform::LinuxOpenRc => {
                let path = "/etc/init.d/sekhmet".to_string();
                let script = "#!/bin/sh\n\
                    set -e\n\
                    rc-service sekhmet stop 2>/dev/null || true\n\
                    rc-update del sekhmet default 2>/dev/null || true\n\
                    rm -f /etc/init.d/sekhmet\n"
                    .to_string();
                Ok((path, script))
            }
            TargetOsPlatform::FreeBsdRc => {
                let path = "/usr/local/etc/rc.d/sekhmet".to_string();
                let script = "#!/bin/sh\n\
                    set -e\n\
                    service sekhmet stop 2>/dev/null || true\n\
                    sysrc -x sekhmet_enable 2>/dev/null || true\n\
                    rm -f /usr/local/etc/rc.d/sekhmet\n"
                    .to_string();
                Ok((path, script))
            }
            TargetOsPlatform::WindowsScm => {
                let path = "C:\\ProgramData\\Sekhmet\\uninstall_service.ps1".to_string();
                let script = "# Windows Service Control Manager (SCM) Teardown for Sekhmet\n\
                    $ErrorActionPreference = 'SilentlyContinue'\n\
                    sc.exe stop SekhmetAuth\n\
                    sc.exe delete SekhmetAuth\n"
                    .to_string();
                Ok((path, script))
            }
            TargetOsPlatform::MacOsLaunchd => {
                let path = "/Library/LaunchDaemons/com.rmediatech.sekhmet.plist".to_string();
                let script = "#!/bin/sh\n\
                    set -e\n\
                    launchctl bootout system /Library/LaunchDaemons/com.rmediatech.sekhmet.plist 2>/dev/null || true\n\
                    rm -f /Library/LaunchDaemons/com.rmediatech.sekhmet.plist\n"
                    .to_string();
                Ok((path, script))
            }
        }
    }
}
