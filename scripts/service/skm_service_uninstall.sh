#!/bin/sh
# ============================================================================
# skm_service_uninstall.sh — Universal POSIX Service Teardown for Sekhmet
# Supports Linux (systemd, OpenRC), FreeBSD (rc.d), and macOS (launchd)
# Standard: SOVEREIGN-RFC-BAREMETAL-01 & OJP
# ============================================================================
set -eu

if [ -f /etc/systemd/system/sekhmet.service ]; then
    systemctl stop sekhmet.service 2>/dev/null || true
    systemctl disable sekhmet.service 2>/dev/null || true
    rm -f /etc/systemd/system/sekhmet.service
    systemctl daemon-reload
    printf '{"status":"uninstalled","platform":"systemd","removed":"/etc/systemd/system/sekhmet.service"}\n'
elif [ -f /etc/init.d/sekhmet ]; then
    rc-service sekhmet stop 2>/dev/null || true
    rc-update del sekhmet default 2>/dev/null || true
    rm -f /etc/init.d/sekhmet
    printf '{"status":"uninstalled","platform":"openrc","removed":"/etc/init.d/sekhmet"}\n'
elif [ -f /usr/local/etc/rc.d/sekhmet ]; then
    service sekhmet stop 2>/dev/null || true
    sysrc -x sekhmet_enable 2>/dev/null || true
    rm -f /usr/local/etc/rc.d/sekhmet
    printf '{"status":"uninstalled","platform":"freebsd_rc","removed":"/usr/local/etc/rc.d/sekhmet"}\n'
elif [ -f /Library/LaunchDaemons/com.rmediatech.sekhmet.plist ]; then
    launchctl bootout system /Library/LaunchDaemons/com.rmediatech.sekhmet.plist 2>/dev/null || true
    rm -f /Library/LaunchDaemons/com.rmediatech.sekhmet.plist
    printf '{"status":"uninstalled","platform":"macos_launchd","removed":"/Library/LaunchDaemons/com.rmediatech.sekhmet.plist"}\n'
else
    printf '{"status":"noop","message":"No installed Sekhmet service unit found."}\n'
fi
