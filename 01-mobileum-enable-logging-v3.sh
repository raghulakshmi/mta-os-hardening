#!/usr/bin/env bash
# ==============================================================================
# Mobileum MTA - 01 Logging & Audit Configuration
# Target OS : Ubuntu Server 24.04 LTS
# Scope     : MTA1 / MTA2
#
# Purpose
# -------
# Establish the local OS logging and audit evidence layer BEFORE:
#   1) Pre-hardening vulnerability assessment
#   2) CIS Level 1 hardening
#   3) Post-hardening vulnerability assessment
#
# Application-specific hardening (including Exim) is intentionally excluded
# and will be handled in a separate script/runbook.
#
# AUDIT IMMUTABILITY POLICY
# -------------------------
# This baseline intentionally does NOT use "-e 2".
# The production MTAs must allow audit-rule changes without requiring a reboot.
# Runtime audit protection relies on root-controlled configuration, file
# permissions, change auditing, sudo logging, and centralized monitoring.
#
#
# This script configures:
#   - Persistent systemd-journald logging
#   - rsyslog service and standard Ubuntu log files
#   - Linux auditd and Mobileum-specific audit rules
#   - Detailed sudo command + I/O logging
#   - Persistent interactive Bash history with timestamps
#   - Normalization of HISTSIZE/HISTFILESIZE in existing Bash admin profiles
#   - sudo.log rotation
#   - Timestamped configuration backups and validation evidence
#
# IMPORTANT DESIGN DECISIONS
# --------------------------
# 1. sudo input logging is intentionally enabled because this is part of the
#    frozen Mobileum baseline. Be aware that sudo input logs can contain secrets
#    typed into stdin. Access to /var/log/sudo-io is therefore root-only.
#
# 2. This script does NOT configure CloudWatch/SIEM forwarding. It establishes
#    the local authoritative logging layer first. Central forwarding can be
#    added after the local baseline is validated.
#
# Usage
# -----
#   sudo bash 01-mobileum-enable-logging.sh
#
#
# Optional variables:
#   SKIP_APT=1                Skip apt update/package installation.
#                             change audit rules afterwards).
#   ALLOW_UNSUPPORTED_OS=1    Permit execution outside Ubuntu 24.04.
#
# The script is intended to be idempotent: running it again rewrites only the
# Mobileum-owned configuration files and preserves/re-backs-up the current state.
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'
umask 027

SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="3.0"
TIMESTAMP="$(date -u +'%Y%m%dT%H%M%SZ')"
HOST_SHORT="$(hostname -s 2>/dev/null || hostname)"

SKIP_APT="${SKIP_APT:-0}"
ALLOW_UNSUPPORTED_OS="${ALLOW_UNSUPPORTED_OS:-0}"

EVIDENCE_BASE="/var/log/mobileum-security/logging"
ROLLBACK_BASE="/var/log/mobileum-security/rollback"
EVIDENCE_DIR="${EVIDENCE_BASE}/${HOST_SHORT}-${TIMESTAMP}"
BACKUP_DIR="${ROLLBACK_BASE}/01-logging-${HOST_SHORT}-${TIMESTAMP}"
RUN_LOG="${EVIDENCE_DIR}/01-logging-run.log"

JOURNALD_DROPIN="/etc/systemd/journald.conf.d/10-mta-logging.conf"
BASH_HISTORY_FILE="/etc/profile.d/mta-history.sh"
SUDOERS_FILE="/etc/sudoers.d/mta-audit"
SUDO_LOG="/var/log/sudo.log"
SUDO_IO_DIR="/var/log/sudo-io"
SUDO_LOGROTATE="/etc/logrotate.d/mta-sudo"
AUDITD_CONF="/etc/audit/auditd.conf"
AUDIT_RULE_FILE="/etc/audit/rules.d/99-mobileum-logging.rules"

# ------------------------------------------------------------------------------
# Utility functions
# ------------------------------------------------------------------------------

log() {
    printf '%s [INFO] %s\n' "$(date +'%F %T')" "$*"
}

warn() {
    printf '%s [WARN] %s\n' "$(date +'%F %T')" "$*" >&2
}

die() {
    printf '%s [ERROR] %s\n' "$(date +'%F %T')" "$*" >&2
    exit 1
}

on_error() {
    local rc=$?
    local line="${1:-unknown}"
    printf '%s [ERROR] Script failed at line %s (exit code %s).\n' \
        "$(date +'%F %T')" "$line" "$rc" >&2
    printf '%s [ERROR] Review: %s\n' "$(date +'%F %T')" "$RUN_LOG" >&2
    exit "$rc"
}
trap 'on_error $LINENO' ERR

require_root() {
    [[ "${EUID}" -eq 0 ]] || die "Run this script as root, e.g. sudo bash ${SCRIPT_NAME}"
}

backup_path() {
    local path="$1"
    if [[ -e "$path" || -L "$path" ]]; then
        log "Backing up ${path}"
        cp -a --parents "$path" "$BACKUP_DIR/"
    fi
}

write_file() {
    # Usage: write_file /path/to/file MODE OWNER GROUP <<'EOF'
    #        content
    #        EOF
    local path="$1"
    local mode="$2"
    local owner="$3"
    local group="$4"
    local tmp

    tmp="$(mktemp)"
    cat > "$tmp"
    install -o "$owner" -g "$group" -m "$mode" "$tmp" "$path"
    rm -f "$tmp"
}

set_auditd_key() {
    # Update one key in auditd.conf without replacing the rest of the packaged
    # configuration. If the key is absent, append it.
    local key="$1"
    local value="$2"

    if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$AUDITD_CONF"; then
        sed -Ei \
            "s|^[[:space:]]*${key}[[:space:]]*=.*$|${key} = ${value}|" \
            "$AUDITD_CONF"
    else
        printf '\n%s = %s\n' "$key" "$value" >> "$AUDITD_CONF"
    fi
}

capture() {
    # Capture a command without allowing an informational/diagnostic command to
    # abort the deployment. Exit status is recorded at the bottom of the file.
    local name="$1"
    shift
    local outfile="${EVIDENCE_DIR}/${name}.txt"
    local rc

    set +e
    {
        printf '# Command:'
        printf ' %q' "$@"
        printf '\n# Captured: %s\n\n' "$(date --iso-8601=seconds)"
        "$@"
        rc=$?
        printf '\n# Exit status: %s\n' "$rc"
    } >"$outfile" 2>&1
    set -e
}

add_watch() {
    # Add an audit watch only when the path currently exists. This keeps the
    # rules portable between MTA build stages and different package states.
    local path="$1"
    local perms="$2"
    local key="$3"

    if [[ -e "$path" || -L "$path" ]]; then
        printf -- '-w %s -p %s -k %s\n' "$path" "$perms" "$key" >> "$AUDIT_RULE_FILE"
    else
        printf '# Skipped because path does not yet exist: %s\n' "$path" >> "$AUDIT_RULE_FILE"
    fi
}

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

normalize_bash_history_file() {
    # Ensure later per-user Bash startup files do not override the Mobileum
    # history limits set in /etc/profile.d/mta-history.sh.
    #
    # Ubuntu's default ~/.bashrc commonly contains:
    #   HISTSIZE=1000
    #   HISTFILESIZE=2000
    #
    # A login shell reads /etc/profile.d first and then the user's startup file,
    # so those later assignments override the system-wide values unless they are
    # normalized here.
    local file="$1"
    local owner="${2:-root}"
    local group="${3:-root}"

    [[ -f "$file" ]] || return 0

    backup_path "$file"

    if grep -Eq '^[[:space:]]*HISTSIZE=' "$file"; then
        sed -Ei 's|^[[:space:]]*HISTSIZE=.*$|HISTSIZE=100000|' "$file"
    else
        printf '\n# Mobileum MTA history limit\nHISTSIZE=100000\n' >> "$file"
    fi

    if grep -Eq '^[[:space:]]*HISTFILESIZE=' "$file"; then
        sed -Ei 's|^[[:space:]]*HISTFILESIZE=.*$|HISTFILESIZE=200000|' "$file"
    else
        printf 'HISTFILESIZE=200000\n' >> "$file"
    fi

    chown "$owner:$group" "$file"
}

# ------------------------------------------------------------------------------
# 0. Preconditions and evidence/backup directories
# ------------------------------------------------------------------------------

require_root

mkdir -p "$EVIDENCE_DIR" "$BACKUP_DIR"
chmod 0700 "$EVIDENCE_DIR" "$BACKUP_DIR"

# From this point onward, also write script output to the evidence run log.
exec > >(tee -a "$RUN_LOG") 2>&1

log "Mobileum MTA Logging & Audit Configuration v${SCRIPT_VERSION}"
log "Host: ${HOST_SHORT}"
log "Evidence directory: ${EVIDENCE_DIR}"
log "Rollback directory: ${BACKUP_DIR}"

[[ "$SKIP_APT" =~ ^[01]$ ]] || die "SKIP_APT must be 0 or 1"
[[ "$ALLOW_UNSUPPORTED_OS" =~ ^[01]$ ]] || die "ALLOW_UNSUPPORTED_OS must be 0 or 1"

if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" ]]; then
        if [[ "$ALLOW_UNSUPPORTED_OS" != "1" ]]; then
            die "This baseline targets Ubuntu 24.04 LTS. Detected ID=${ID:-unknown}, VERSION_ID=${VERSION_ID:-unknown}. Set ALLOW_UNSUPPORTED_OS=1 only if intentional."
        fi
        warn "Running on unsupported OS because ALLOW_UNSUPPORTED_OS=1."
    fi
else
    die "/etc/os-release is not readable."
fi

capture "00-os-release-before" cat /etc/os-release
capture "00-hostnamectl-before" hostnamectl
capture "00-date-uptime-before" bash -c 'date --iso-8601=seconds; uptime; who -a'

# Back up everything this script owns/modifies.
mkdir -p /etc/systemd/journald.conf.d /etc/sudoers.d /etc/audit/rules.d
backup_path "$JOURNALD_DROPIN"
backup_path "$BASH_HISTORY_FILE"
backup_path "$SUDOERS_FILE"
backup_path "$SUDO_LOGROTATE"
backup_path "$AUDITD_CONF"
backup_path "$AUDIT_RULE_FILE"
backup_path "/etc/audit/rules.d"
backup_path "/etc/rsyslog.conf"
backup_path "/etc/rsyslog.d"

# ------------------------------------------------------------------------------
# 1. Install/confirm logging packages
# ------------------------------------------------------------------------------

if [[ "$SKIP_APT" == "0" ]]; then
    log "Refreshing apt package metadata."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update

    log "Installing/confirming rsyslog, auditd and logrotate."
    apt-get install -y --no-install-recommends rsyslog auditd logrotate

    # audispd-plugins is useful for future audit event forwarding/integration,
    # but the local logging baseline does not depend on it. Do not fail the
    # whole build if Universe is not enabled in a particular image.
    if apt-cache show audispd-plugins >/dev/null 2>&1; then
        log "Installing audispd-plugins for future audit dispatcher integration."
        if ! apt-get install -y --no-install-recommends audispd-plugins; then
            warn "audispd-plugins installation failed; local auditd logging is unaffected."
        fi
    else
        warn "audispd-plugins is not available from configured repositories; continuing."
    fi
else
    log "SKIP_APT=1: package installation skipped."
fi

for cmd in journalctl systemctl rsyslogd auditctl augenrules ausearch aureport visudo; do
    has_cmd "$cmd" || die "Required command not found after package setup: ${cmd}"
done

# ------------------------------------------------------------------------------
# 2. Persistent interactive Bash history
# ------------------------------------------------------------------------------

log "Configuring persistent interactive Bash history."

write_file "$BASH_HISTORY_FILE" 0644 root root <<'EOF'
# ============================================================
# MTA interactive Bash history configuration
# ============================================================

# Large persistent command history
export HISTSIZE=100000
export HISTFILESIZE=200000

# Add timestamps to history
export HISTTIMEFORMAT='%F %T '

# Append rather than overwrite history on shell exit
shopt -s histappend

# Immediately append commands from this terminal to ~/.bash_history,
# then import commands written by other active terminals.
#
# This allows multiple SSH/terminal sessions for the same account
# to contribute to the same history instead of overwriting each other.
PROMPT_COMMAND="history -a; history -n${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
EOF

# Ubuntu's default user ~/.bashrc sets HISTSIZE=1000 and HISTFILESIZE=2000.
# Because ~/.bashrc is processed after /etc/profile.d for a normal login flow,
# those values can override the Mobileum system-wide baseline.
#
# Normalize existing interactive Bash users so the final effective values stay
# at 100000 / 200000. We also normalize root and /etc/skel for consistency and
# for any future local Bash users created from the standard skeleton.
log "Normalizing Bash history limits in existing Bash user profiles."

# Root profile (useful for sudo -i; direct root SSH should remain disabled).
if [[ -f /root/.bashrc ]]; then
    normalize_bash_history_file /root/.bashrc root root
fi

# Future users created from /etc/skel.
if [[ -f /etc/skel/.bashrc ]]; then
    normalize_bash_history_file /etc/skel/.bashrc root root
fi

# Existing non-system users whose configured login shell is Bash.
while IFS=: read -r username _ uid gid _ home shell; do
    [[ "$uid" =~ ^[0-9]+$ ]] || continue
    (( uid >= 1000 )) || continue
    [[ "$shell" == */bash ]] || continue
    [[ -d "$home" ]] || continue

    user_group="$(id -gn "$username" 2>/dev/null || printf '%s' "$gid")"
    normalize_bash_history_file "$home/.bashrc" "$username" "$user_group"
done < /etc/passwd

# This profile.d file applies to NEW interactive Bash shells. Existing sessions
# must reconnect/start a new shell before validation.
capture "02-bash-history-file" cat "$BASH_HISTORY_FILE"
capture "02-bash-history-stat" stat "$BASH_HISTORY_FILE"
capture "02-bash-history-overrides" bash -c '
    echo "### /etc/profile.d/mta-history.sh ###"
    cat /etc/profile.d/mta-history.sh
    echo
    echo "### HISTSIZE/HISTFILESIZE assignments in Bash startup files ###"
    grep -RnsE "^[[:space:]]*(HISTSIZE|HISTFILESIZE)=" \
        /root/.bashrc /etc/skel/.bashrc /home/*/.bashrc 2>/dev/null || true
'

# ------------------------------------------------------------------------------
# 3. systemd-journald persistent logging
# ------------------------------------------------------------------------------

log "Configuring systemd-journald."

write_file "$JOURNALD_DROPIN" 0644 root root <<'EOF'
[Journal]

# Persist logs across reboot
Storage=persistent

# Compress journal data
Compress=yes

# Enable Forward Secure Sealing when sealing keys are available
Seal=yes

# Protect root filesystem from uncontrolled journal growth
SystemMaxUse=2G
SystemKeepFree=2G

# Retain journal records for a maximum of 30 days
MaxRetentionSec=30day

# Rotate individual journal files at least daily
MaxFileSec=1day

# Protect journald itself during log storms.
# Ubuntu 24.04/systemd uses per-service rate limiting.
# This MTA permits a larger burst because SMTP is Internet-facing.
RateLimitIntervalSec=30s
RateLimitBurst=20000

# Forward journal messages to rsyslog where applicable
ForwardToSyslog=yes

# Ensure kernel auditing is enabled.
# auditd is still the primary audit daemon.
Audit=yes
EOF

# Storage=persistent normally creates /var/log/journal automatically. Creating
# the directory explicitly before restart ensures persistence can start now.
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal || true

log "Restarting journald to apply the drop-in."
systemctl restart systemd-journald
journalctl --flush || true

# ------------------------------------------------------------------------------
# 4. rsyslog
# ------------------------------------------------------------------------------

log "Enabling rsyslog."

# We intentionally preserve Ubuntu's packaged facility routing rather than
# adding duplicate rules for auth.log/kern.log/mail.log/syslog.
# journald's ForwardToSyslog=yes feeds applicable records to rsyslog.
rsyslogd -N1
systemctl enable --now rsyslog
systemctl restart rsyslog

# Create test records to confirm the pipeline. These are clearly tagged and are
# harmless evidence messages.
logger -p user.notice     -t mobileum-logging-test "MOBILEUM_USER_LOG_TEST ${HOST_SHORT} ${TIMESTAMP}"
logger -p authpriv.notice -t mobileum-logging-test "MOBILEUM_AUTH_LOG_TEST ${HOST_SHORT} ${TIMESTAMP}"
logger -p mail.notice     -t mobileum-logging-test "MOBILEUM_MAIL_LOG_TEST ${HOST_SHORT} ${TIMESTAMP}"

sleep 1

# ------------------------------------------------------------------------------
# 5. Detailed sudo logging and I/O recording
# ------------------------------------------------------------------------------

log "Configuring detailed sudo command and I/O logging."

# SECURITY NOTE:
#   log_input records terminal/stdin input and can therefore capture passwords,
#   tokens or other secrets typed into commands. It is enabled because it is
#   part of the frozen Mobileum baseline. /var/log/sudo-io is root-only.
write_file "$SUDOERS_FILE" 0440 root root <<'EOF'
# Mobileum MTA detailed sudo audit logging
Defaults log_output
Defaults logfile="/var/log/sudo.log"
Defaults log_input
Defaults iolog_dir="/var/log/sudo-io"
Defaults use_pty
EOF

# Validate this file first, then the entire sudoers configuration, BEFORE
# relying on it.
visudo -cf "$SUDOERS_FILE"
visudo -c

touch "$SUDO_LOG"
chown root:root "$SUDO_LOG"
chmod 0600 "$SUDO_LOG"

mkdir -p "$SUDO_IO_DIR"
chown root:root "$SUDO_IO_DIR"
chmod 0700 "$SUDO_IO_DIR"

# Rotate the text sudo.log. sudo I/O sessions are directory-based and are not
# managed by traditional logrotate; their retention must be governed separately
# once Mobileum's central-retention requirement is finalized.
write_file "$SUDO_LOGROTATE" 0644 root root <<'EOF'
/var/log/sudo.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
}
EOF

logrotate -d "$SUDO_LOGROTATE" >"${EVIDENCE_DIR}/05-sudo-logrotate-debug.txt" 2>&1 || true

# ------------------------------------------------------------------------------
# 6. auditd daemon configuration
# ------------------------------------------------------------------------------

log "Configuring auditd daemon settings."

# Preserve all packaged/current auditd.conf settings and change ONLY the values
# previously frozen for Mobileum.
#
# NOTE:
#   The actual numeric max_log_file, space_left and admin_space_left thresholds
#   are intentionally not invented here. Existing values remain in force.
#   CIS L1 review may later tighten the disk-full response policy.
set_auditd_key "space_left_action"       "SYSLOG"
set_auditd_key "admin_space_left_action" "SYSLOG"
set_auditd_key "disk_full_action"        "SYSLOG"
set_auditd_key "max_log_file_action"     "ROTATE"
set_auditd_key "num_logs"                "10"

chown root:root "$AUDITD_CONF"
chmod 0640 "$AUDITD_CONF"

systemctl enable --now auditd

# auditd supports SIGHUP to re-read auditd.conf without a full service restart.
log "Sending SIGHUP to auditd to re-read auditd.conf."
systemctl kill -s HUP auditd.service
sleep 1

# ------------------------------------------------------------------------------
# 7. Mobileum audit rules
# ------------------------------------------------------------------------------

log "Building Mobileum audit rule set."

# Start a fresh Mobileum-owned rule file. augenrules merges all *.rules files;
# -D, -b, -f and -e are normalized into their proper positions in the final
# /etc/audit/audit.rules file.
cat > "$AUDIT_RULE_FILE" <<'EOF'
# ==============================================================================
# Mobileum MTA audit rules
# ==============================================================================
# Clear previously loaded rules when the merged ruleset is loaded.
-D

# Kernel audit queue sized for an Internet-facing MTA.
-b 8192

# Failure mode 1 = printk. This is the previously frozen Mobileum baseline.
-f 1

# ------------------------------------------------------------------------------
# File/directory watches are added below by the deployment script only when the
# path exists on this host.
# ------------------------------------------------------------------------------
EOF

# Identity/account databases
add_watch /etc/passwd      wa identity
add_watch /etc/group       wa identity
add_watch /etc/shadow      wa identity
add_watch /etc/gshadow     wa identity
add_watch /etc/security/opasswd wa identity

# sudo policy and sudo evidence
add_watch /etc/sudoers     wa sudo_policy
add_watch /etc/sudoers.d   wa sudo_policy
add_watch /var/log/sudo.log wa sudo_log

# SSH server configuration
add_watch /etc/ssh/sshd_config   wa ssh_config
add_watch /etc/ssh/sshd_config.d wa ssh_config


# Network configuration
add_watch /etc/netplan     wa network_config
add_watch /etc/hosts       wa network_config
add_watch /etc/hostname    wa network_config

# systemd/service configuration
add_watch /etc/systemd/system wa systemd_config

# Scheduled jobs
add_watch /etc/crontab      wa cron_config
add_watch /etc/cron.d       wa cron_config
add_watch /etc/cron.hourly  wa cron_config
add_watch /etc/cron.daily   wa cron_config
add_watch /etc/cron.weekly  wa cron_config
add_watch /etc/cron.monthly wa cron_config

# PAM/security policy
add_watch /etc/pam.d    wa pam_config
add_watch /etc/security wa security_config

# AppArmor policy
add_watch /etc/apparmor   wa apparmor_config
add_watch /etc/apparmor.d wa apparmor_config

# Linux Audit configuration itself
add_watch /etc/audit wa audit_config

# Package/repository configuration and package management executables
add_watch /etc/apt          wa package_config
add_watch /usr/bin/apt      x  package_mgmt
add_watch /usr/bin/apt-get  x  package_mgmt
add_watch /usr/bin/dpkg     x  package_mgmt

# Common privileged administrative tools
add_watch /usr/bin/sudo x privileged_tool
add_watch /usr/bin/su   x privileged_tool

# Kernel module utilities
add_watch /usr/sbin/insmod   x kernel_modules
add_watch /usr/sbin/rmmod    x kernel_modules
add_watch /usr/sbin/modprobe x kernel_modules
add_watch /usr/bin/kmod      x kernel_modules

# Time zone configuration
add_watch /etc/localtime wa time_change

cat >> "$AUDIT_RULE_FILE" <<'EOF'

# ------------------------------------------------------------------------------
# Syscall rules
# ------------------------------------------------------------------------------

EOF

# Syscall audit architecture selection.
MACHINE_ARCH="$(uname -m)"
AUDIT_ARCHES=("b64")
case "$MACHINE_ARCH" in
    x86_64|amd64)
        # x86_64 can execute both 64-bit and 32-bit userspace; audit both.
        AUDIT_ARCHES=("b64" "b32")
        ;;
    aarch64|arm64)
        AUDIT_ARCHES=("b64")
        ;;
    *)
        warn "Architecture ${MACHINE_ARCH} not explicitly profiled; using arch=b64 rules."
        AUDIT_ARCHES=("b64")
        ;;
esac

for a in "${AUDIT_ARCHES[@]}"; do
    cat >> "$AUDIT_RULE_FILE" <<EOF
# Time changes (${a})
-a always,exit -F arch=${a} -S adjtimex,settimeofday -k time_change
-a always,exit -F arch=${a} -S clock_settime -F a0=0 -k time_change

# Host/domain identity changes (${a})
-a always,exit -F arch=${a} -S sethostname,setdomainname -k system_locale

# Mount activity by interactive users (${a})
-a always,exit -F arch=${a} -S mount -F auid>=1000 -F auid!=unset -k mounts

# Destructive file operations by interactive users (${a})
-a always,exit -F arch=${a} -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=unset -k delete

# Root command execution attributable to an interactive/non-system login (${a})
# This complements sudo I/O logging and remains useful even when an admin
# obtains a root shell and subsequently runs commands without invoking sudo.
-a always,exit -F arch=${a} -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k privileged

EOF
done

# Kernel module loading is uncommon and security-sensitive. Audit the native
# 64-bit syscalls; command-level module utilities are watched above as well.
cat >> "$AUDIT_RULE_FILE" <<'EOF'
# Kernel module changes
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_modules
EOF

cat >> "$AUDIT_RULE_FILE" <<'EOF'

# IMPORTANT OPERATIONAL POLICY:
# Do NOT use "-e 2" (immutable audit configuration) on these MTAs.
# Mobileum requires future audit-rule changes to be possible without rebooting
# a running production mail system.
EOF

chown root:root "$AUDIT_RULE_FILE"
chmod 0600 "$AUDIT_RULE_FILE"

# If the kernel is already immutable for any reason, the script cannot safely
# change live audit rules without a reboot. Treat that as an operational
# exception rather than enabling immutability ourselves.
CURRENT_AUDIT_ENABLED="$(auditctl -s 2>/dev/null | awk '$1=="enabled" {print $2; exit}')"
CURRENT_AUDIT_ENABLED="${CURRENT_AUDIT_ENABLED:-unknown}"

if [[ "$CURRENT_AUDIT_ENABLED" == "2" ]]; then
    die "Kernel audit configuration is already immutable (enabled=2). This baseline requires modifiable audit rules without reboot."
fi

log "Compiling and loading audit rules with augenrules."
augenrules --check || true
augenrules --load

# Give auditd a moment to drain initial configuration events.
sleep 1

# ------------------------------------------------------------------------------
# 8. Validation and evidence capture
# ------------------------------------------------------------------------------

log "Collecting post-configuration evidence."

capture "08-services" bash -c '
    systemctl --no-pager --full status systemd-journald || true
    echo
    systemctl --no-pager --full status rsyslog || true
    echo
    systemctl --no-pager --full status auditd || true
'

capture "08-enabled-services" bash -c '
    systemctl is-enabled systemd-journald 2>&1 || true
    systemctl is-enabled rsyslog 2>&1 || true
    systemctl is-enabled auditd 2>&1 || true
'

capture "08-journald-effective-config" systemd-analyze cat-config systemd/journald.conf
capture "08-journal-disk-usage" journalctl --disk-usage
capture "08-journal-verify" journalctl --verify

capture "08-rsyslog-syntax" rsyslogd -N1
capture "08-rsyslog-config" bash -c '
    printf "### /etc/rsyslog.conf ###\n"
    cat /etc/rsyslog.conf
    printf "\n### /etc/rsyslog.d/*.conf ###\n"
    for f in /etc/rsyslog.d/*.conf; do
        [ -e "$f" ] || continue
        echo "----- $f -----"
        cat "$f"
    done
'

capture "08-sudoers-validation" visudo -c
capture "08-sudoers-mobileum" cat "$SUDOERS_FILE"
capture "08-sudoreplay-list" sudoreplay -l

capture "08-audit-status" auditctl -s
capture "08-audit-rules" auditctl -l
capture "08-auditd-selected-config" bash -c \
    "grep -E '^[[:space:]]*(log_file|max_log_file|max_log_file_action|num_logs|space_left|space_left_action|admin_space_left|admin_space_left_action|disk_full_action|disk_error_action|flush|freq)[[:space:]]*=' '$AUDITD_CONF' || true"
capture "08-audit-rule-file" cat "$AUDIT_RULE_FILE"
capture "08-audit-summary" aureport --summary

capture "08-important-file-permissions" bash -c "
    stat '$BASH_HISTORY_FILE' '$JOURNALD_DROPIN' '$SUDOERS_FILE' '$SUDO_LOG' '$SUDO_IO_DIR' '$AUDITD_CONF' '$AUDIT_RULE_FILE' '$SUDO_LOGROTATE'
"

capture "08-log-files" bash -c '
    for f in \
        /var/log/syslog \
        /var/log/auth.log \
        /var/log/kern.log \
        /var/log/mail.log \
        /var/log/dpkg.log \
        /var/log/apt/history.log \
        /var/log/audit/audit.log \
        /var/log/sudo.log
    do
        if [ -e "$f" ]; then
            ls -lh "$f"
        else
            printf "MISSING: %s\n" "$f"
        fi
    done
'

capture "08-log-directory-usage" bash -c '
    du -sh /var/log/journal 2>/dev/null || true
    du -sh /var/log/audit 2>/dev/null || true
    du -sh /var/log/sudo-io 2>/dev/null || true
    du -sh /var/log/mobileum-security 2>/dev/null || true
'

capture "08-recent-logins" last -n 20
capture "08-recent-failed-logins" lastb -n 20
capture "08-warning-journal-current-boot" journalctl -p warning -b --no-pager
capture "08-kernel-journal-current-boot" journalctl -k -b --no-pager

capture "08-test-records-journal" journalctl -t mobileum-logging-test --since "-10 minutes" --no-pager
capture "08-test-records-files" bash -c '
    grep -H "MOBILEUM_.*_LOG_TEST" /var/log/syslog /var/log/auth.log /var/log/mail.log 2>/dev/null || true
'

capture "08-installed-logging-packages" bash -c \
    "dpkg-query -W -f='\${binary:Package}\t\${Version}\n' rsyslog auditd audispd-plugins logrotate 2>&1 || true"

# ------------------------------------------------------------------------------
# 9. Health checks that should fail the script if core logging is not healthy
# ------------------------------------------------------------------------------

log "Running mandatory health checks."

systemctl is-active --quiet systemd-journald || die "systemd-journald is not active."
systemctl is-active --quiet rsyslog         || die "rsyslog is not active."
systemctl is-active --quiet auditd          || die "auditd is not active."

visudo -c >/dev/null
rsyslogd -N1 >/dev/null 2>&1

AUDIT_LOST="$(auditctl -s | awk '$1=="lost" {print $2; exit}')"
AUDIT_BACKLOG_LIMIT="$(auditctl -s | awk '$1=="backlog_limit" {print $2; exit}')"
AUDIT_ENABLED="$(auditctl -s | awk '$1=="enabled" {print $2; exit}')"

[[ "${AUDIT_LOST:-unknown}" == "0" ]] \
    || warn "auditctl reports lost=${AUDIT_LOST:-unknown}. Investigate before proceeding to PRE-VA."

[[ "${AUDIT_BACKLOG_LIMIT:-unknown}" == "8192" ]] \
    || warn "Expected audit backlog_limit=8192; current=${AUDIT_BACKLOG_LIMIT:-unknown}."

cat >> "$AUDIT_RULE_FILE" <<'EOF'

# IMPORTANT OPERATIONAL POLICY:
# Do NOT use "-e 2" (immutable audit configuration) on these MTAs.
# Mobileum requires future audit-rule changes to be possible without rebooting
# a running production mail system.
EOF

# ------------------------------------------------------------------------------
# 10. Operator summary
# ------------------------------------------------------------------------------

cat <<EOF

==============================================================================
 Mobileum MTA - 01 Logging & Audit Configuration COMPLETE
==============================================================================

Host                     : ${HOST_SHORT}
UTC run timestamp        : ${TIMESTAMP}
Evidence                 : ${EVIDENCE_DIR}
Rollback/config backups  : ${BACKUP_DIR}

Configured:
  [OK] Persistent journald
       Storage=persistent
       Compress=yes
       Seal=yes
       SystemMaxUse=2G
       SystemKeepFree=2G
       MaxRetentionSec=30day
       MaxFileSec=1day
       RateLimitIntervalSec=30s
       RateLimitBurst=20000
       ForwardToSyslog=yes
       Audit=yes

  [OK] rsyslog enabled and syntax-validated

  [OK] Bash admin history
       HISTSIZE=100000
       HISTFILESIZE=200000
       Timestamp display enabled
       histappend + cross-session history append/import
       Existing Bash user ~/.bashrc values normalized to 100000/200000

  [OK] Detailed sudo logging
       ${SUDO_LOG}
       ${SUDO_IO_DIR}
       log_input + log_output + use_pty

  [OK] auditd enabled
       backlog_limit target = 8192
       failure mode target  = 1
       rotation             = ROTATE / 10 logs
       disk-space actions   = SYSLOG (frozen baseline)

  [OK] Mobileum audit rules
       identity/security files
       sudo policy + sudo log
       SSH configuration
       network configuration
       systemd configuration
       cron configuration
       PAM/security policy
       AppArmor policy
       audit configuration
       package management
       time/hostname changes
       mounts
       destructive file operations
       attributable root command execution
       kernel-module changes

Current kernel audit state : ${AUDIT_ENABLED:-unknown}
Audit lost records         : ${AUDIT_LOST:-unknown}

IMPORTANT NEXT CHECKS
---------------------
1. Open a NEW SSH session before testing Bash history, because profile.d settings
   apply to new interactive shells.

2. In the new session verify:
       echo "\$HISTSIZE"
       echo "\$HISTFILESIZE"
       echo "\$HISTTIMEFORMAT"
       shopt histappend
       echo "\$PROMPT_COMMAND"

3. Run a harmless sudo command as the normal administrator:
       sudo whoami

   Then verify:
       sudo tail -50 /var/log/sudo.log
       sudo sudoreplay -l

4. Verify audit events:
       sudo ausearch -k privileged -ts recent -i
       sudo ausearch -k sudo_policy -ts recent -i
       sudo auditctl -s

5. Do NOT enable "-e 2" on these MTAs. Audit rules must remain changeable
   at runtime because future production changes cannot depend on a reboot.

6. This script does not reboot the server and does not alter SSH/network access.

Next stage:
       02 - PRE-HARDENING VULNERABILITY / CONFIGURATION ASSESSMENT

==============================================================================
EOF

exit 0
