#!/usr/bin/env bash
# ==============================================================================
# Mobileum Internet-Facing MTA - 03 OS Hardening
# File    : 03-mobileum-cis-l1-os-hardening-v1.3.sh
# Version : 1.3
# Target  : Ubuntu Server 24.04 LTS on AWS EC2
# Scope   : CIS Ubuntu Linux 24.04 LTS Level 1-aligned OS hardening
#           with Mobileum/DriveIT project exceptions.
#
# IMPORTANT PROJECT EXCEPTIONS / DESIGN DECISIONS
# -----------------------------------------------
# 1. Exim is intentionally OUT OF SCOPE. Exim hardening is a separate activity.
# 2. SSH daemon hardening is NOT changed by this script. Access must remain
#    available while OS hardening is staged and validated.
# 3. Existing 01 logging/audit controls are preserved, including:
#      - journald ForwardToSyslog=yes
#      - audit enabled=1 (no immutable -e 2)
#    These are deliberate project decisions and may differ from a literal CIS
#    benchmark recommendation. Therefore this script is "CIS L1-aligned", not a
#    claim of formal CIS certification or 100% benchmark compliance.
# 4. AWS reverse-path filtering is NOT changed. rp_filter=2 (loose mode) is
#    preserved because multi-ENI/asymmetric routing may be introduced.
# 5. Filesystem repartitioning (/tmp, /var, /var/log, /home, etc.) is not done
#    on a running MTA. Such controls are handled as build-time/manual controls.
# 6. Service/package removal is never automatic. Candidates are reported and
#    can be disabled only with explicit --disable-service arguments.
# 7. PAM and firewall changes are separate, explicit high-risk modules.
#
# RECOMMENDED EXECUTION SEQUENCE
# ------------------------------
#   sudo ./03-mobileum-cis-l1-os-hardening-v1.3.sh --check
#   sudo ./03-mobileum-cis-l1-os-hardening-v1.3.sh --apply-safe
#   sudo ./03-mobileum-cis-l1-os-hardening-v1.3.sh --check
#
#   # PAM only after console/SSM recovery path is confirmed:
#   sudo ./03-mobileum-cis-l1-os-hardening-v1.3.sh --apply-pam
#
#   # Firewall only after AWS SG roles are corrected/confirmed.
#   # The script auto-detects MTA1/MTA2/Jumpbox and uses the approved IP map.
#   sudo ./03-mobileum-cis-l1-os-hardening-v1.3.sh --apply-firewall
#
#   # Optional controlled operations:
#   sudo ./03-mobileum-cis-l1-os-hardening-v1.3.sh --install-security-updates
#   sudo ./03-mobileum-cis-l1-os-hardening-v1.3.sh \
#        --disable-service ModemManager.service \
#        --disable-service open-vm-tools.service
#
# NOTE: Do NOT disable a service simply because it appears in the example.
#       Validate the role of each service on the actual MTA first.
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="1.3"
RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
HOST_SHORT="$(hostname -s 2>/dev/null || hostname)"

EVIDENCE_ROOT="/var/log/mobileum-security/hardening"
EVIDENCE_DIR="${EVIDENCE_ROOT}/${HOST_SHORT}-${RUN_TS}"
BACKUP_ROOT="/var/backups/mobileum-os-hardening"
BACKUP_DIR="${BACKUP_ROOT}/${HOST_SHORT}-${RUN_TS}"
LOG_FILE="${EVIDENCE_DIR}/03-hardening-run.log"
SUMMARY_FILE="${EVIDENCE_DIR}/HARDENING-SUMMARY.txt"
STATUS_FILE="${EVIDENCE_DIR}/CONTROL-STATUS.tsv"

APPLY_SAFE=0
APPLY_PAM=0
APPLY_FIREWALL=0
RESET_FIREWALL=0
INSTALL_SECURITY_UPDATES=0
CHECK_ONLY=0
FORCE_OS=0

# ------------------------------------------------------------------------------
# Mobileum approved network identity map (2026-09-16)
# ------------------------------------------------------------------------------
MTA1_HOST="mta1.mobileum.com"
MTA1_IP="172.31.27.243"
MTA2_HOST="mta2.mobileum.com"
MTA2_IP="172.31.28.75"
JUMPBOX_IP="172.31.25.209"
OFFICE_PUBLIC_IP="45.119.114.19"
AWS_CONNECT_PUBLIC_IP="52.22.247.175"

# Firewall role is auto-detected from hostname/local private IP. It can be
# explicitly overridden only when required for recovery/testing.
FIREWALL_ROLE="auto"
DETECTED_FIREWALL_ROLE="unknown"
PEER_MTA_IP=""
SSH_TRUST_CIDRS=()
MGMT_CIDRS=()
SMTP_CIDRS=()
MONITOR_CIDRS=()
DISABLE_SERVICES=()

# Project policy values used by the PAM module.
PASS_MAX_DAYS=365
PASS_MIN_DAYS=1
PASS_WARN_AGE=7
FAILLOCK_DENY=5
FAILLOCK_INTERVAL=900
FAILLOCK_UNLOCK=900
FAILLOCK_ROOT_UNLOCK=900
PASSWORD_HISTORY=24
PASSWORD_MINLEN=14

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
CHANGE_COUNT=0
SKIP_COUNT=0

usage() {
    cat <<'USAGE'
Usage:
  sudo ./03-mobileum-cis-l1-os-hardening-v1.3.sh [options]

Modes / actions:
  --check                   Assessment only; make no intentional configuration changes.
  --apply-safe              Apply low-risk OS hardening controls.
  --apply-pam               Apply PAM/password/account hardening (HIGH IMPACT).
  --apply-firewall          Configure and enable UFW (HIGH IMPACT).
  --reset-firewall          Explicitly clear pre-existing UFW rules before applying
                            the Mobileum baseline. Required if old UFW rules exist.
  --install-security-updates  Install only packages offered from an Ubuntu security pocket.
  --disable-service NAME    Disable/mask an explicitly approved service. Repeatable.

Firewall inputs:
  --firewall-role ROLE      auto|mta1|mta2|jumpbox. Default: auto.
                            Auto-detection uses hostname/local private IP.
  --mgmt-cidr CIDR          Additional approved source CIDR allowed to TCP/22. Repeatable.
                            Normally omit on MTAs; office access terminates at the jumpbox.
  --smtp-cidr CIDR          Additional/alternate source CIDR allowed to TCP/25 on MTAs.
                            If omitted, TCP/25 is allowed from anywhere on MTA1/MTA2.
  --monitor-cidr CIDR       Source CIDR allowed to TCP/9100 for node_exporter.
                            Repeatable. No 9100 rule is added if omitted.

Embedded approved SSH trust:
  MTA1 172.31.27.243 : SSH from jumpbox 172.31.25.209 + MTA2 172.31.28.75
  MTA2 172.31.28.75  : SSH from jumpbox 172.31.25.209 + MTA1 172.31.27.243
  Jumpbox 172.31.25.209 : SSH from office 45.119.114.19 + aws-connect 52.22.247.175

Other:
  --force-os                Permit execution if OS detection is not Ubuntu 24.04.
  -h, --help                Show this help.

Examples:
  sudo ./03-mobileum-cis-l1-os-hardening-v1.3.sh --check
  sudo ./03-mobileum-cis-l1-os-hardening-v1.3.sh --apply-safe
  sudo ./03-mobileum-cis-l1-os-hardening-v1.3.sh --apply-pam
  # On MTA1/MTA2/Jumpbox the role and approved SSH source IPs are auto-detected:
  sudo ./03-mobileum-cis-l1-os-hardening-v1.3.sh --apply-firewall

  # Optional explicit role override (only when hostname/IP auto-detection cannot work):
  sudo ./03-mobileum-cis-l1-os-hardening-v1.3.sh --apply-firewall --firewall-role mta1

Safety notes:
  * No Exim settings are changed.
  * No sshd settings are changed.
  * No audit immutability (-e 2) is added.
  * rp_filter is not changed.
  * Existing services are not removed unless explicitly named.
  * Repartitioning/mount restructuring is not performed.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check) CHECK_ONLY=1 ;;
        --apply-safe) APPLY_SAFE=1 ;;
        --apply-pam) APPLY_PAM=1 ;;
        --apply-firewall) APPLY_FIREWALL=1 ;;
        --reset-firewall) RESET_FIREWALL=1 ;;
        --install-security-updates) INSTALL_SECURITY_UPDATES=1 ;;
        --firewall-role)
            [[ $# -ge 2 ]] || { echo "ERROR: --firewall-role requires a value" >&2; exit 2; }
            FIREWALL_ROLE="$2"; shift ;;
        --mgmt-cidr)
            [[ $# -ge 2 ]] || { echo "ERROR: --mgmt-cidr requires a value" >&2; exit 2; }
            MGMT_CIDRS+=("$2"); shift ;;
        --smtp-cidr)
            [[ $# -ge 2 ]] || { echo "ERROR: --smtp-cidr requires a value" >&2; exit 2; }
            SMTP_CIDRS+=("$2"); shift ;;
        --monitor-cidr)
            [[ $# -ge 2 ]] || { echo "ERROR: --monitor-cidr requires a value" >&2; exit 2; }
            MONITOR_CIDRS+=("$2"); shift ;;
        --disable-service)
            [[ $# -ge 2 ]] || { echo "ERROR: --disable-service requires a unit name" >&2; exit 2; }
            DISABLE_SERVICES+=("$2"); shift ;;
        --force-os) FORCE_OS=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: Unknown option: $1" >&2; usage; exit 2 ;;
    esac
    shift
done

if (( CHECK_ONLY == 0 && APPLY_SAFE == 0 && APPLY_PAM == 0 && APPLY_FIREWALL == 0 && INSTALL_SECURITY_UPDATES == 0 && ${#DISABLE_SERVICES[@]} == 0 )); then
    CHECK_ONLY=1
fi

case "$FIREWALL_ROLE" in
    auto|mta1|mta2|jumpbox) ;;
    *)
        echo "ERROR: --firewall-role must be auto, mta1, mta2, or jumpbox." >&2
        exit 2
        ;;
esac

if [[ ${EUID} -ne 0 ]]; then
    echo "ERROR: Run as root, for example: sudo ./${SCRIPT_NAME} --check" >&2
    exit 1
fi

mkdir -p "$EVIDENCE_DIR" "$BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"
chmod 0750 "$EVIDENCE_ROOT" "$EVIDENCE_DIR" 2>/dev/null || true
: > "$STATUS_FILE"
printf 'Control\tResult\tDetail\n' >> "$STATUS_FILE"

exec > >(tee -a "$LOG_FILE") 2>&1

log()  { printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
info() { log "INFO  $*"; }
pass() { PASS_COUNT=$((PASS_COUNT+1)); log "PASS  $*"; }
warn() { WARN_COUNT=$((WARN_COUNT+1)); log "WARN  $*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT+1)); log "FAIL  $*"; }
changed() { CHANGE_COUNT=$((CHANGE_COUNT+1)); log "CHG   $*"; }
skip() { SKIP_COUNT=$((SKIP_COUNT+1)); log "SKIP  $*"; }

record_status() {
    local control="$1" result="$2" detail="$3"
    printf '%s\t%s\t%s\n' "$control" "$result" "$detail" >> "$STATUS_FILE"
}

backup_path() {
    local path="$1"
    [[ -e "$path" || -L "$path" ]] || return 0
    local dest="${BACKUP_DIR}${path}"
    mkdir -p "$(dirname "$dest")"
    cp -a "$path" "$dest"
}

backup_command_output() {
    local name="$1"; shift
    "$@" > "${BACKUP_DIR}/${name}" 2>&1 || true
}

on_error() {
    local rc=$? line=$1
    fail "Unexpected error at line ${line}; exit code=${rc}. Review ${LOG_FILE} and backup ${BACKUP_DIR}."
    record_status "script_runtime" "FAIL" "line=${line}; rc=${rc}"
    write_summary || true
    exit "$rc"
}
trap 'on_error $LINENO' ERR

write_summary() {
    {
        echo "=============================================================================="
        echo " MOBILEUM MTA - 03 OS HARDENING SUMMARY"
        echo "=============================================================================="
        echo "Host                : ${HOST_SHORT}"
        echo "UTC Run ID          : ${RUN_TS}"
        echo "Script              : ${SCRIPT_NAME} v${SCRIPT_VERSION}"
        echo "Evidence            : ${EVIDENCE_DIR}"
        echo "Backup              : ${BACKUP_DIR}"
        echo
        echo "Requested actions:"
        echo "  check-only        : ${CHECK_ONLY}"
        echo "  apply-safe        : ${APPLY_SAFE}"
        echo "  apply-pam         : ${APPLY_PAM}"
        echo "  apply-firewall    : ${APPLY_FIREWALL}"
        echo "  reset-firewall    : ${RESET_FIREWALL}"
        echo "  install-security-updates : ${INSTALL_SECURITY_UPDATES}"
        echo "  firewall-role req : ${FIREWALL_ROLE}"
        echo "  firewall-role det : ${DETECTED_FIREWALL_ROLE}"
        echo "  jumpbox-private   : ${JUMPBOX_IP}"
        echo "  peer-mta-private  : ${PEER_MTA_IP:-n/a}"
        echo "  office-public     : ${OFFICE_PUBLIC_IP}"
        echo "  aws-connect       : ${AWS_CONNECT_PUBLIC_IP}"
        echo "  disable-services  : ${DISABLE_SERVICES[*]:-none}"
        echo
        echo "Counters:"
        echo "  PASS               : ${PASS_COUNT}"
        echo "  WARN               : ${WARN_COUNT}"
        echo "  FAIL               : ${FAIL_COUNT}"
        echo "  CHANGED            : ${CHANGE_COUNT}"
        echo "  SKIPPED            : ${SKIP_COUNT}"
        echo
        echo "Project exceptions retained:"
        echo "  - Exim hardening excluded"
        echo "  - SSH daemon settings unchanged"
        echo "  - journald ForwardToSyslog=yes preserved from 01"
        echo "  - audit runtime remains modifiable; no audit -e 2"
        echo "  - AWS rp_filter setting is not changed"
        echo "  - no automatic filesystem repartitioning"
        echo "  - no automatic service removal"
        echo "  - upgradeable != vulnerability; security-pocket updates are classified separately"
        echo "  - MTA SSH host firewall trust: jumpbox private IP + peer MTA private IP"
        echo "  - Jumpbox SSH host firewall trust: office public /32 + aws-connect public /32"
        echo
        echo "This is a CIS Level 1-aligned implementation baseline, not formal CIS certification."
        echo "=============================================================================="
    } > "$SUMMARY_FILE"
}
trap write_summary EXIT

validate_cidr() {
    local cidr="$1"
    python3 - "$cidr" <<'PY' >/dev/null 2>&1
import ipaddress, sys
ipaddress.ip_network(sys.argv[1], strict=False)
PY
}

set_kv_file() {
    local file="$1" key="$2" value="$3"
    mkdir -p "$(dirname "$file")"
    touch "$file"
    if grep -Eq "^[[:space:]]*${key}[[:space:]]+" "$file"; then
        sed -ri "s|^[[:space:]]*${key}[[:space:]]+.*|${key} ${value}|" "$file"
    else
        printf '%s %s\n' "$key" "$value" >> "$file"
    fi
}

set_login_defs() {
    local key="$1" value="$2"
    local file="/etc/login.defs"
    if grep -Eq "^[[:space:]]*${key}[[:space:]]+" "$file"; then
        sed -ri "s|^[[:space:]]*${key}[[:space:]]+.*|${key}\t${value}|" "$file"
    else
        printf '%s\t%s\n' "$key" "$value" >> "$file"
    fi
}

check_os() {
    info "Checking operating system and platform."
    source /etc/os-release
    echo "ID=${ID:-unknown}" > "${EVIDENCE_DIR}/01-os.txt"
    echo "VERSION_ID=${VERSION_ID:-unknown}" >> "${EVIDENCE_DIR}/01-os.txt"
    uname -a >> "${EVIDENCE_DIR}/01-os.txt"
    systemd-detect-virt >> "${EVIDENCE_DIR}/01-os.txt" 2>&1 || true

    if [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]]; then
        pass "Ubuntu 24.04 detected."
        record_status "os_version" "PASS" "Ubuntu 24.04"
    elif (( FORCE_OS == 1 )); then
        warn "OS is ${ID:-unknown} ${VERSION_ID:-unknown}; continuing because --force-os was supplied."
        record_status "os_version" "WARN" "forced on ${ID:-unknown} ${VERSION_ID:-unknown}"
    else
        fail "This script is intended for Ubuntu 24.04. Detected ${ID:-unknown} ${VERSION_ID:-unknown}."
        record_status "os_version" "FAIL" "unsupported OS"
        exit 1
    fi
}

capture_pre_state() {
    info "Capturing pre-change state."
    backup_path /etc/sysctl.d
    backup_path /etc/security
    backup_path /etc/pam.d
    backup_path /usr/share/pam-configs
    backup_path /etc/login.defs
    backup_path /etc/default/ufw
    backup_path /etc/ufw
    backup_path /etc/sudoers
    backup_path /etc/sudoers.d
    backup_path /etc/systemd/coredump.conf
    backup_path /etc/systemd/coredump.conf.d

    backup_command_output dpkg-selections.txt dpkg --get-selections
    backup_command_output apt-manual.txt apt-mark showmanual
    backup_command_output services-enabled.txt systemctl list-unit-files --state=enabled
    backup_command_output services-running.txt systemctl list-units --type=service --state=running
    backup_command_output sysctl-pre.txt sysctl -a
    backup_command_output ufw-pre.txt ufw status verbose
    backup_command_output audit-status-pre.txt auditctl -s
    backup_command_output audit-rules-pre.txt auditctl -l
    backup_command_output mounts-pre.txt findmnt
    backup_command_output network-pre.txt ip addr
    ip route > "${BACKUP_DIR}/routes-pre.txt" 2>&1 || true

    local backup_test_tar="/tmp/mobileum-backup-integrity-${RUN_TS}-$$.tar"
    tar -C "$BACKUP_DIR" -cf "$backup_test_tar" . >/dev/null 2>&1
    tar -tf "$backup_test_tar" >/dev/null
    rm -f "$backup_test_tar"
    pass "Configuration backup created and integrity check passed: ${BACKUP_DIR}"
    record_status "backup" "PASS" "$BACKUP_DIR"
}

check_01_invariants() {
    info "Verifying that 01 logging/audit controls are present and remain mutable."

    if command -v auditctl >/dev/null 2>&1; then
        auditctl -s > "${EVIDENCE_DIR}/02-audit-status.txt" 2>&1 || true
        auditctl -l > "${EVIDENCE_DIR}/02-audit-rules.txt" 2>&1 || true
        local enabled lost
        enabled="$(auditctl -s 2>/dev/null | awk '$1=="enabled"{print $2}')"
        lost="$(auditctl -s 2>/dev/null | awk '$1=="lost"{print $2}')"
        if [[ "$enabled" == "1" && "$lost" == "0" ]]; then
            pass "auditd runtime healthy: enabled=1, lost=0."
            record_status "audit_health" "PASS" "enabled=1 lost=0"
        else
            warn "auditd status differs from project target (enabled=${enabled:-?}, lost=${lost:-?})."
            record_status "audit_health" "WARN" "enabled=${enabled:-?} lost=${lost:-?}"
        fi
    else
        warn "auditctl not found. 01 audit controls cannot be validated."
        record_status "audit_health" "WARN" "auditctl missing"
    fi

    if [[ -f /etc/systemd/journald.conf.d/10-mta-logging.conf ]] && \
       grep -Eq '^[[:space:]]*ForwardToSyslog[[:space:]]*=[[:space:]]*yes' /etc/systemd/journald.conf.d/10-mta-logging.conf; then
        pass "01 journald ForwardToSyslog=yes project setting present."
        record_status "journald_project_exception" "PASS" "ForwardToSyslog=yes retained"
    else
        warn "Expected 01 journald project drop-in/ForwardToSyslog=yes not detected."
        record_status "journald_project_exception" "WARN" "not detected"
    fi
}

apply_safe_sysctl() {
    local file="/etc/sysctl.d/60-mobileum-cis-l1.conf"
    info "Applying conservative network/kernel sysctl baseline."
    backup_path "$file"

    cat > "$file" <<'SYSCTL'
# Mobileum MTA - CIS Level 1-aligned conservative sysctl baseline
# Managed by 03-mobileum-cis-l1-os-hardening-v1.3.sh
#
# IMPORTANT: rp_filter is intentionally NOT set here. AWS loose mode (2) is
# retained to avoid breaking multi-ENI or asymmetric routing designs.

# Memory / link protection
kernel.randomize_va_space = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# MTA is not a router
net.ipv4.ip_forward = 0
net.ipv4.conf.all.forwarding = 0

# Source-routed traffic is not required
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore ICMP redirects and do not send redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Spoof/anomaly visibility and basic TCP hardening
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
SYSCTL
    chmod 0644 "$file"

    # Apply only the project file; do not blindly reload every vendor sysctl file.
    while IFS='=' read -r raw_key raw_value; do
        local key value
        key="$(echo "$raw_key" | xargs)"
        value="$(echo "$raw_value" | sed 's/#.*//' | xargs)"
        [[ -n "$key" && -n "$value" ]] || continue
        [[ "$key" == \#* ]] && continue
        if [[ -e "/proc/sys/${key//./\/}" ]]; then
            sysctl -w "${key}=${value}" >/dev/null
        else
            warn "sysctl ${key} not available on this kernel; skipped runtime apply."
        fi
    done < <(grep -Ev '^[[:space:]]*(#|$)' "$file")

    changed "Conservative sysctl baseline written to ${file}."
    record_status "sysctl_hardening" "CHANGED" "$file"
}

apply_safe_cron_permissions() {
    info "Applying conservative cron ownership/permission controls."
    local path
    for path in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        [[ -e "$path" ]] || continue
        backup_path "$path"
        chown -R root:root "$path"
        if [[ -d "$path" ]]; then
            chmod 0700 "$path"
        else
            chmod 0600 "$path"
        fi
    done
    changed "Cron configuration ownership/permissions normalized."
    record_status "cron_permissions" "CHANGED" "root-owned; crontab 0600; cron dirs 0700"
}

apply_safe_core_permissions() {
    info "Validating core identity database permissions."
    # Apply only well-established Ubuntu-compatible permissions.
    [[ -f /etc/passwd ]]  && chown root:root /etc/passwd  && chmod 0644 /etc/passwd
    [[ -f /etc/group ]]   && chown root:root /etc/group   && chmod 0644 /etc/group
    [[ -f /etc/shadow ]]  && chown root:shadow /etc/shadow && chmod 0640 /etc/shadow
    [[ -f /etc/gshadow ]] && chown root:shadow /etc/gshadow && chmod 0640 /etc/gshadow
    changed "Core identity database ownership/permissions normalized."
    record_status "identity_permissions" "CHANGED" "/etc/passwd,/etc/group,/etc/shadow,/etc/gshadow"
}

apply_safe_apparmor() {
    info "Ensuring AppArmor remains enabled."
    if systemctl list-unit-files apparmor.service >/dev/null 2>&1; then
        systemctl enable --now apparmor.service >/dev/null
        if systemctl is-active --quiet apparmor.service; then
            pass "AppArmor service active."
            record_status "apparmor" "PASS" "active/enabled"
        else
            fail "AppArmor did not become active."
            record_status "apparmor" "FAIL" "inactive"
        fi
    else
        warn "apparmor.service not present."
        record_status "apparmor" "WARN" "service absent"
    fi
}

apply_safe_sudo_policy() {
    local file="/etc/sudoers.d/91-mobileum-cis-l1"
    info "Ensuring sudo re-authentication timeout remains within a conservative limit."
    backup_path "$file"
    cat > "$file" <<'SUDO'
# Mobileum MTA - CIS Level 1-aligned sudo policy
# Preserve 01 use_pty/logfile/session I/O settings in /etc/sudoers.d/mta-audit.
Defaults timestamp_timeout=15
SUDO
    chmod 0440 "$file"
    chown root:root "$file"
    if visudo -cf /etc/sudoers >/dev/null; then
        changed "Sudo timestamp_timeout=15 configured; sudoers syntax valid."
        record_status "sudo_timeout" "CHANGED" "15 minutes"
    else
        fail "sudoers syntax validation failed; restoring project file."
        rm -f "$file"
        if [[ -f "${BACKUP_DIR}${file}" ]]; then
            mkdir -p "$(dirname "$file")"
            cp -a "${BACKUP_DIR}${file}" "$file"
        fi
        record_status "sudo_timeout" "FAIL" "visudo validation failed"
        return 1
    fi
}

apply_safe() {
    info "=== APPLY SAFE OS CONTROLS ==="
    apply_safe_sysctl
    apply_safe_cron_permissions
    apply_safe_core_permissions
    apply_safe_apparmor
    apply_safe_sudo_policy
}

configure_pam_profiles() {
    local profile

    # pam_faillock authfail profile
    profile="/usr/share/pam-configs/mobileum-faillock"
    cat > "$profile" <<'PAM'
Name: Mobileum faillock authfail
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
 [default=die] pam_faillock.so authfail
PAM

    # pam_faillock preauth/account profile
    profile="/usr/share/pam-configs/mobileum-faillock-notify"
    cat > "$profile" <<'PAM'
Name: Mobileum faillock preauth and account
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
 requisite pam_faillock.so preauth
Account-Type: Primary
Account:
 required pam_faillock.so
PAM

    # pwquality profile
    profile="/usr/share/pam-configs/mobileum-pwquality"
    cat > "$profile" <<'PAM'
Name: Mobileum pwquality password strength checking
Default: yes
Priority: 1024
Conflicts: cracklib
Password-Type: Primary
Password:
 requisite pam_pwquality.so retry=3
PAM

    # pwhistory profile
    profile="/usr/share/pam-configs/mobileum-pwhistory"
    cat > "$profile" <<PAM
Name: Mobileum password history checking
Default: yes
Priority: 1024
Password-Type: Primary
Password:
 requisite pam_pwhistory.so remember=${PASSWORD_HISTORY} enforce_for_root try_first_pass use_authtok
PAM
}

harden_pam_unix_profile() {
    info "Hardening the Ubuntu pam_unix profile: remove nullok and ensure use_authtok/yescrypt in the password stack."
    local profile="/usr/share/pam-configs/unix"
    [[ -f "$profile" ]] || { warn "${profile} not found; pam_unix profile hardening skipped."; return 0; }

    python3 - "$profile" <<'PYPROFILE'
from pathlib import Path
import re, sys
path = Path(sys.argv[1])
lines = path.read_text().splitlines()
out = []
section = None
subsection = None
for line in lines:
    if re.match(r'^\S+-Type:', line):
        section = line.split('-Type:',1)[0].strip().lower()
        subsection = None
    stripped = line.strip()
    if section == 'password' and stripped == 'Password:':
        subsection = 'password'
    elif section == 'password' and stripped == 'Password-Initial:':
        subsection = 'password-initial'

    if 'pam_unix.so' in line:
        # nullok is not permitted in any pam_unix authentication line.
        line = re.sub(r'(?<!\S)nullok(?!\S)', '', line)
        line = re.sub(r'[ \t]+$', '', line)
        line = re.sub(r' {2,}', ' ', line) if line.startswith(' ') else line

        if section == 'password':
            tokens = line.split()
            if subsection == 'password':
                for option in ('use_authtok', 'try_first_pass', 'yescrypt'):
                    if option not in tokens:
                        tokens.append(option)
                indent = '        ' if line[:1].isspace() else ''
                line = indent + ' '.join(tokens)
            elif subsection == 'password-initial':
                if 'yescrypt' not in tokens and 'sha512' not in tokens:
                    tokens.append('yescrypt')
                indent = '        ' if line[:1].isspace() else ''
                line = indent + ' '.join(tokens)
    out.append(line)
path.write_text('\n'.join(out) + '\n')
PYPROFILE
}

remove_pam_unix_nullok_from_generated_files() {
    local f
    for f in /etc/pam.d/common-auth /etc/pam.d/common-password; do
        [[ -f "$f" ]] || continue
        sed -ri 's/(pam_unix\.so[^#\r\n]*)\bnullok\b/\1/g; s/[[:space:]]+$//' "$f"
    done
}

validate_pam_stack() {
    local ok=1
    grep -Eq 'pam_faillock\.so' /etc/pam.d/common-auth || ok=0
    grep -Eq 'pam_faillock\.so' /etc/pam.d/common-account || ok=0
    grep -Eq 'pam_pwquality\.so' /etc/pam.d/common-password || ok=0
    grep -Eq 'pam_pwhistory\.so' /etc/pam.d/common-password || ok=0
    if grep -Eq 'pam_unix\.so.*\bnullok\b' /etc/pam.d/common-auth /etc/pam.d/common-password 2>/dev/null; then
        ok=0
    fi
    grep -Eq '^password[[:space:]].*pam_unix\.so.*\buse_authtok\b' /etc/pam.d/common-password || ok=0
    grep -Eq '^password[[:space:]].*pam_unix\.so.*\b(yescrypt|sha512)\b' /etc/pam.d/common-password || ok=0

    if (( ok == 1 )); then
        pass "PAM stack contains faillock, pwquality and pwhistory; pam_unix nullok is absent and use_authtok/strong hashing are present."
        record_status "pam_stack" "PASS" "faillock/pwquality/pwhistory active; pam_unix nullok absent; use_authtok + strong hash present"
        return 0
    fi

    fail "PAM post-validation failed. Restore /etc/pam.d and /usr/share/pam-configs from ${BACKUP_DIR} before ending the recovery session."
    record_status "pam_stack" "FAIL" "post-validation failed"
    return 1
}

apply_pam() {
    info "=== APPLY PAM / ACCOUNT CONTROLS (HIGH IMPACT) ==="
    warn "Keep the current administrative session open until PAM validation is complete."
    warn "A console or AWS SSM recovery path is strongly recommended."

    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y libpam-modules libpam-modules-bin libpam-pwquality

    # Password quality policy
    mkdir -p /etc/security/pwquality.conf.d
    cat > /etc/security/pwquality.conf.d/50-mobileum.conf <<PWC
# Mobileum MTA local password quality policy
minlen = ${PASSWORD_MINLEN}
difok = 2
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
maxsequence = 3
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
enforce_for_root
retry = 3
PWC
    chmod 0644 /etc/security/pwquality.conf.d/50-mobileum.conf

    # Password history policy: keep options in the preferred config file too.
    cat > /etc/security/pwhistory.conf <<PWH
# Mobileum MTA password history policy
remember = ${PASSWORD_HISTORY}
enforce_for_root
PWH
    chmod 0644 /etc/security/pwhistory.conf

    # Failed authentication policy
    cat > /etc/security/faillock.conf <<FLC
# Mobileum MTA authentication failure policy
deny = ${FAILLOCK_DENY}
fail_interval = ${FAILLOCK_INTERVAL}
unlock_time = ${FAILLOCK_UNLOCK}
even_deny_root
root_unlock_time = ${FAILLOCK_ROOT_UNLOCK}
FLC
    chmod 0644 /etc/security/faillock.conf

    configure_pam_profiles
    harden_pam_unix_profile

    # Regenerate common-* using the explicit project profiles. --force is used
    # only after the complete PAM directory/profile backup above.
    pam-auth-update --force --enable \
        mobileum-faillock \
        mobileum-faillock-notify \
        mobileum-pwquality \
        mobileum-pwhistory

    # Defensive cleanup of generated files after profile regeneration.
    remove_pam_unix_nullok_from_generated_files

    # Account aging defaults for NEW local accounts.
    set_login_defs PASS_MAX_DAYS "$PASS_MAX_DAYS"
    set_login_defs PASS_MIN_DAYS "$PASS_MIN_DAYS"
    set_login_defs PASS_WARN_AGE "$PASS_WARN_AGE"

    # Apply aging to existing, unlocked local password accounts only.
    # Key-only / locked cloud accounts are not modified.
    while IFS=: read -r user _ uid _ _ _ shell; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        (( uid == 0 || uid >= 1000 )) || continue
        case "$shell" in
            */nologin|*/false) continue ;;
        esac
        local shadow_hash
        shadow_hash="$(getent shadow "$user" | cut -d: -f2 || true)"
        [[ -n "$shadow_hash" ]] || continue
        [[ "$shadow_hash" == '!'* || "$shadow_hash" == '*'* ]] && continue
        chage --maxdays "$PASS_MAX_DAYS" --mindays "$PASS_MIN_DAYS" --warndays "$PASS_WARN_AGE" "$user"
        info "Applied password aging to unlocked local account: ${user}"
    done < <(getent passwd)

    validate_pam_stack
    changed "PAM/password/account hardening applied."
    record_status "pam_hardening" "CHANGED" "policy applied and validated"
}

write_aws_sg_guidance() {
    local out="${EVIDENCE_DIR}/AWS-SECURITY-GROUP-DESIGN.txt"
    cat > "$out" <<SGDOC
MOBILEUM RECOMMENDED AWS SECURITY GROUP SEPARATION
=================================================

APPROVED ADDRESS MAP
--------------------
MTA1      : ${MTA1_HOST} / ${MTA1_IP}
MTA2      : ${MTA2_HOST} / ${MTA2_IP}
Jumpbox   : ${JUMPBOX_IP}
Office    : ${OFFICE_PUBLIC_IP}/32
aws-connect public source : ${AWS_CONNECT_PUBLIC_IP}/32

1) SG-Mobileum-MTA
   Assign ONLY to MTA1 and MTA2.

   Recommended inbound:
     - TCP/25 from 0.0.0.0/0 if MTA1/MTA2 are the Internet MX tier.
     - TCP/22 from SG-Mobileum-Jumpbox.
     - TCP/22 from SG-Mobileum-MTA itself (self-reference) for MTA1 <-> MTA2 SSH.
     - Monitoring ports only from the approved monitoring server/SG.

   Do NOT add ${OFFICE_PUBLIC_IP}/32 or ${AWS_CONNECT_PUBLIC_IP}/32 directly to the MTA SG.

2) SG-Mobileum-Jumpbox
   Assign ONLY to the jumpbox.

   Recommended inbound:
     - TCP/22 from ${OFFICE_PUBLIC_IP}/32 (DriveIT office).
     - TCP/22 from ${AWS_CONNECT_PUBLIC_IP}/32 (aws-connect), provided this is a stable
       public/EIP source. If that address can change, replace it with stable private AWS
       connectivity or a stable Elastic IP before production cutover.

   Recommended outbound:
     - TCP/22 to SG-Mobileum-MTA (or default outbound if that is the approved AWS policy).

3) IMPORTANT CORRECTION
   Do NOT assign one identical SG to Jumpbox + MTA1 + MTA2. Jumpbox and MTA are different
   security roles. MTA1 and MTA2 may share SG-Mobileum-MTA because their role is identical.

HOST UFW SECOND LAYER
---------------------
MTA1 (${MTA1_IP}) TCP/22 sources:
  - ${JUMPBOX_IP}/32
  - ${MTA2_IP}/32

MTA2 (${MTA2_IP}) TCP/22 sources:
  - ${JUMPBOX_IP}/32
  - ${MTA1_IP}/32

Jumpbox (${JUMPBOX_IP}) TCP/22 sources:
  - ${OFFICE_PUBLIC_IP}/32
  - ${AWS_CONNECT_PUBLIC_IP}/32
SGDOC
    record_status "aws_sg_design" "INFO" "$out"
}

detect_firewall_role() {
    local local_ips host_fqdn host_short role="unknown"
    local_ips="$(hostname -I 2>/dev/null || true)"
    host_fqdn="$(hostname -f 2>/dev/null || true)"
    host_short="$(hostname -s 2>/dev/null || hostname)"

    if [[ "$FIREWALL_ROLE" != "auto" ]]; then
        role="$FIREWALL_ROLE"
    elif [[ " $local_ips " == *" ${MTA1_IP} "* || "$host_fqdn" == "$MTA1_HOST" || "$host_short" == "mta1" ]]; then
        role="mta1"
    elif [[ " $local_ips " == *" ${MTA2_IP} "* || "$host_fqdn" == "$MTA2_HOST" || "$host_short" == "mta2" ]]; then
        role="mta2"
    elif [[ " $local_ips " == *" ${JUMPBOX_IP} "* || "$host_short" == *jumpbox* ]]; then
        role="jumpbox"
    fi

    DETECTED_FIREWALL_ROLE="$role"
    SSH_TRUST_CIDRS=()
    PEER_MTA_IP=""

    case "$role" in
        mta1)
            PEER_MTA_IP="$MTA2_IP"
            SSH_TRUST_CIDRS=("${JUMPBOX_IP}/32" "${MTA2_IP}/32")
            ;;
        mta2)
            PEER_MTA_IP="$MTA1_IP"
            SSH_TRUST_CIDRS=("${JUMPBOX_IP}/32" "${MTA1_IP}/32")
            ;;
        jumpbox)
            SSH_TRUST_CIDRS=("${OFFICE_PUBLIC_IP}/32" "${AWS_CONNECT_PUBLIC_IP}/32")
            ;;
        *)
            ;;
    esac

}

configure_firewall() {
    info "=== APPLY HOST FIREWALL (HIGH IMPACT) ==="
    warn "UFW will use default deny incoming / deny routed / allow outgoing."

    local role cidr
    detect_firewall_role
    role="$DETECTED_FIREWALL_ROLE"
    if [[ "$role" == "unknown" ]]; then
        fail "Firewall role cannot be safely identified from hostname/local IP. Refusing to enable UFW."
        info "Expected identities: MTA1=${MTA1_IP}, MTA2=${MTA2_IP}, Jumpbox=${JUMPBOX_IP}."
        info "If this is one of those hosts but naming differs, rerun with --firewall-role mta1|mta2|jumpbox."
        record_status "ufw" "FAIL" "unknown firewall role"
        return 1
    fi

    info "Firewall role: ${role}"
    info "Approved SSH sources: ${SSH_TRUST_CIDRS[*]}"

    for cidr in "${SSH_TRUST_CIDRS[@]}" "${MGMT_CIDRS[@]}" "${SMTP_CIDRS[@]}" "${MONITOR_CIDRS[@]}"; do
        [[ -n "$cidr" ]] || continue
        if ! validate_cidr "$cidr"; then
            fail "Invalid CIDR: ${cidr}"
            record_status "ufw" "FAIL" "invalid CIDR ${cidr}"
            return 1
        fi
    done

    export DEBIAN_FRONTEND=noninteractive
    if ! command -v ufw >/dev/null 2>&1; then
        apt-get update
        apt-get install -y ufw
    fi

    local pre_status existing_rules
    pre_status="$(ufw status 2>/dev/null | head -1 || true)"
    existing_rules="$(ufw show added 2>/dev/null || true)"

    if grep -Eq '^ufw[[:space:]]' <<< "$existing_rules"; then
        if (( RESET_FIREWALL == 1 )); then
            warn "Existing UFW rules detected; --reset-firewall supplied, so they will be replaced by the Mobileum role baseline."
            printf '%s\n' "$existing_rules" > "${EVIDENCE_DIR}/ufw-existing-rules-before-reset.txt"
            ufw --force reset
        else
            fail "Existing UFW rules detected. Refusing to layer new rules over an unknown policy. Review ${EVIDENCE_DIR}/ufw-existing-rules.txt and rerun with --reset-firewall only after approval."
            printf '%s\n' "$existing_rules" > "${EVIDENCE_DIR}/ufw-existing-rules.txt"
            record_status "ufw" "FAIL" "existing rules present; explicit --reset-firewall required"
            return 1
        fi
    elif grep -qi 'Status: active' <<< "$pre_status"; then
        warn "UFW is active but no explicit added rules were reported. Applying the approved role baseline."
    fi

    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny routed
    ufw logging medium

    # Always establish approved SSH access BEFORE enabling UFW.
    for cidr in "${SSH_TRUST_CIDRS[@]}"; do
        case "$role" in
            mta1|mta2)
                ufw allow proto tcp from "$cidr" to any port 22 comment "Mobileum ${role} SSH trusted source"
                ;;
            jumpbox)
                ufw allow proto tcp from "$cidr" to any port 22 comment 'Mobileum jumpbox SSH trusted source'
                ;;
        esac
    done

    # Explicit additional management exception, if approved.
    for cidr in "${MGMT_CIDRS[@]}"; do
        ufw allow proto tcp from "$cidr" to any port 22 comment 'Mobileum additional management exception'
    done

    # SMTP belongs only on MTA hosts. Jumpbox never receives this rule.
    if [[ "$role" == "mta1" || "$role" == "mta2" ]]; then
        if (( ${#SMTP_CIDRS[@]} == 0 )); then
            ufw allow 25/tcp comment 'Mobileum Internet SMTP'
        else
            for cidr in "${SMTP_CIDRS[@]}"; do
                ufw allow proto tcp from "$cidr" to any port 25 comment 'Mobileum MTA SMTP approved source'
            done
        fi
    fi

    # Optional monitoring access. No rule exists unless the source is supplied.
    for cidr in "${MONITOR_CIDRS[@]}"; do
        ufw allow proto tcp from "$cidr" to any port 9100 comment 'Mobileum node exporter'
    done

    ufw --force enable
    ufw status verbose > "${EVIDENCE_DIR}/ufw-post.txt"
    ufw show added > "${EVIDENCE_DIR}/ufw-post-added.txt" 2>&1 || true

    if grep -q 'Status: active' "${EVIDENCE_DIR}/ufw-post.txt"; then
        pass "UFW active for role=${role}. Verify a NEW SSH connection before closing the current session."
        changed "Host firewall enabled for ${role}."
        record_status "ufw" "CHANGED" "role=${role}; SSH=${SSH_TRUST_CIDRS[*]}"
    else
        fail "UFW did not become active."
        record_status "ufw" "FAIL" "not active"
        return 1
    fi
}

classify_updates() {
    local raw_out="$1" tsv_out="$2"
    : > "$raw_out"
    printf 'Package\tRepositories\tCandidate\tArchitecture\tInstalled\tClassification\n' > "$tsv_out"

    apt list --upgradable 2>/dev/null | sed '1{/^Listing/d;}' > "$raw_out" || true

    local line pkg_repo pkg repos candidate arch installed class
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        [[ "$line" == *"upgradable from:"* ]] || continue
        pkg_repo="${line%% *}"
        pkg="${pkg_repo%%/*}"
        repos="${pkg_repo#*/}"
        candidate="$(awk '{print $2}' <<< "$line")"
        arch="$(awk '{print $3}' <<< "$line")"
        installed="$(sed -n 's/.*\[upgradable from: \([^]]*\)\].*/\1/p' <<< "$line")"

        if [[ "$repos" == *security* ]]; then
            class="SECURITY_POCKET"
        elif [[ "$repos" == *updates* ]]; then
            class="STANDARD_UPDATE"
        elif [[ "$repos" == *backports* ]]; then
            class="BACKPORT"
        else
            class="OTHER_OR_THIRD_PARTY"
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$pkg" "$repos" "$candidate" "$arch" "$installed" "$class" >> "$tsv_out"
    done < "$raw_out"
}

candidate_version_from_security_pocket() {
    local pkg="$1" candidate="$2"
    apt-cache madison "$pkg" 2>/dev/null | awk -F'|' -v want="$candidate" '
        {
            v=$2; src=$3;
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", v);
            if (v==want && src ~ /-security([\/[:space:]]|$)/) found=1
        }
        END { exit(found ? 0 : 1) }
    '
}

install_security_updates() {
    info "=== INSTALL VERIFIED UBUNTU SECURITY-POCKET CANDIDATES ONLY ==="
    info "Refreshing APT metadata before security-update classification."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update

    local raw="${EVIDENCE_DIR}/updates-before-security-install.txt"
    local tsv="${EVIDENCE_DIR}/updates-before-security-install.tsv"
    local approved="${EVIDENCE_DIR}/security-updates-approved.tsv"
    local skipped="${EVIDENCE_DIR}/security-updates-skipped.tsv"
    classify_updates "$raw" "$tsv"
    printf 'Package\tCandidate\tReason\n' > "$approved"
    printf 'Package\tCandidate\tReason\n' > "$skipped"

    local pkg candidate
    local install_specs=()
    while IFS=$'\t' read -r pkg _repos candidate _arch _installed class; do
        [[ "$pkg" == "Package" ]] && continue
        [[ "$class" == "SECURITY_POCKET" ]] || continue

        if candidate_version_from_security_pocket "$pkg" "$candidate"; then
            install_specs+=("${pkg}=${candidate}")
            printf '%s\t%s\t%s\n' "$pkg" "$candidate" 'exact APT candidate verified in Ubuntu security pocket' >> "$approved"
        else
            printf '%s\t%s\t%s\n' "$pkg" "$candidate" 'repository list mentioned security, but exact candidate was not verified from -security; manual review' >> "$skipped"
        fi
    done < "$tsv"

    if (( ${#install_specs[@]} == 0 )); then
        pass "No exact Ubuntu security-pocket candidate versions require automatic installation."
        record_status "security_updates" "PASS" "0 exact security candidates"
        return 0
    fi

    info "Exact security-pocket candidate package/version specs selected (${#install_specs[@]}): ${install_specs[*]}"
    apt-get install -y --only-upgrade "${install_specs[@]}"
    changed "Installed ${#install_specs[@]} exact package candidate(s) verified from an Ubuntu security pocket."

    # Re-classify after installation for evidence.
    classify_updates "${EVIDENCE_DIR}/updates-after-security-install.txt" "${EVIDENCE_DIR}/updates-after-security-install.tsv"

    if [[ -f /var/run/reboot-required ]]; then
        warn "A reboot is required by installed updates. Do NOT reboot until the approved MTA change window."
        cp -a /var/run/reboot-required* "${EVIDENCE_DIR}/" 2>/dev/null || true
        record_status "security_updates" "WARN" "installed; reboot-required"
    else
        pass "Verified security-pocket updates installed; no reboot-required marker present."
        record_status "security_updates" "CHANGED" "installed; no reboot marker"
    fi
}

disable_approved_services() {
    (( ${#DISABLE_SERVICES[@]} > 0 )) || return 0
    info "=== DISABLE EXPLICITLY APPROVED SERVICES ==="
    local svc
    for svc in "${DISABLE_SERVICES[@]}"; do
        if ! systemctl list-unit-files "$svc" --no-legend 2>/dev/null | grep -q .; then
            warn "Requested service ${svc} is not installed; skipped."
            record_status "service:${svc}" "SKIP" "not installed"
            continue
        fi
        systemctl disable --now "$svc" || true
        systemctl mask "$svc" || true
        if systemctl is-enabled "$svc" 2>/dev/null | grep -Eq 'masked|disabled'; then
            changed "Disabled/masked approved service: ${svc}"
            record_status "service:${svc}" "CHANGED" "disabled/masked"
        else
            warn "Could not confirm disabled/masked state for ${svc}."
            record_status "service:${svc}" "WARN" "state uncertain"
        fi
    done
}

check_sysctl() {
    info "Checking network/kernel security values."
    local -A expected=(
        [kernel.randomize_va_space]=2
        [fs.protected_hardlinks]=1
        [fs.protected_symlinks]=1
        [net.ipv4.ip_forward]=0
        [net.ipv4.conf.all.forwarding]=0
        [net.ipv4.conf.all.accept_source_route]=0
        [net.ipv4.conf.default.accept_source_route]=0
        [net.ipv4.conf.all.accept_redirects]=0
        [net.ipv4.conf.default.accept_redirects]=0
        [net.ipv4.conf.all.secure_redirects]=0
        [net.ipv4.conf.default.secure_redirects]=0
        [net.ipv4.conf.all.send_redirects]=0
        [net.ipv4.conf.default.send_redirects]=0
        [net.ipv4.conf.all.log_martians]=1
        [net.ipv4.conf.default.log_martians]=1
        [net.ipv4.icmp_echo_ignore_broadcasts]=1
        [net.ipv4.icmp_ignore_bogus_error_responses]=1
        [net.ipv4.tcp_syncookies]=1
        [net.ipv6.conf.all.accept_source_route]=0
        [net.ipv6.conf.default.accept_source_route]=0
        [net.ipv6.conf.all.accept_redirects]=0
        [net.ipv6.conf.default.accept_redirects]=0
    )

    : > "${EVIDENCE_DIR}/sysctl-check.txt"
    local key want got
    for key in "${!expected[@]}"; do
        want="${expected[$key]}"
        if [[ ! -e "/proc/sys/${key//./\/}" ]]; then
            printf '%s\tN/A\t%s\n' "$key" "$want" >> "${EVIDENCE_DIR}/sysctl-check.txt"
            continue
        fi
        got="$(sysctl -n "$key" 2>/dev/null || echo '?')"
        printf '%s\t%s\t%s\n' "$key" "$got" "$want" >> "${EVIDENCE_DIR}/sysctl-check.txt"
        if [[ "$got" == "$want" ]]; then
            pass "${key}=${got}"
        else
            warn "${key}=${got}; target=${want}"
        fi
    done

    local rp_all rp_def
    rp_all="$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo N/A)"
    rp_def="$(sysctl -n net.ipv4.conf.default.rp_filter 2>/dev/null || echo N/A)"
    info "AWS project exception: rp_filter all=${rp_all}, default=${rp_def}; script does not change it."
    record_status "rp_filter_exception" "INFO" "all=${rp_all}; default=${rp_def}; unchanged"
}

check_pam() {
    info "Checking PAM/account policy."
    local pam_ok=1
    grep -Eq 'pam_faillock\.so' /etc/pam.d/common-auth 2>/dev/null || pam_ok=0
    grep -Eq 'pam_faillock\.so' /etc/pam.d/common-account 2>/dev/null || pam_ok=0
    grep -Eq 'pam_pwquality\.so' /etc/pam.d/common-password 2>/dev/null || pam_ok=0
    grep -Eq 'pam_pwhistory\.so' /etc/pam.d/common-password 2>/dev/null || pam_ok=0
    if grep -Eq 'pam_unix\.so.*\bnullok\b' /etc/pam.d/common-auth /etc/pam.d/common-password 2>/dev/null; then
        pam_ok=0
    fi
    grep -Eq '^password[[:space:]].*pam_unix\.so.*\buse_authtok\b' /etc/pam.d/common-password 2>/dev/null || pam_ok=0
    grep -Eq '^password[[:space:]].*pam_unix\.so.*\b(yescrypt|sha512)\b' /etc/pam.d/common-password 2>/dev/null || pam_ok=0
    if (( pam_ok == 1 )); then
        pass "PAM module baseline appears hardened."
        record_status "pam_check" "PASS" "required modules present; nullok absent"
    else
        warn "PAM baseline is not yet fully hardened. Use --apply-pam only after recovery access is confirmed."
        record_status "pam_check" "WARN" "remediation pending"
    fi

    grep -E '^[[:space:]]*PASS_(MAX_DAYS|MIN_DAYS|WARN_AGE)' /etc/login.defs > "${EVIDENCE_DIR}/login-defs-aging.txt" 2>/dev/null || true
}

check_firewall() {
    info "Checking host firewall."
    local role
    detect_firewall_role
    role="$DETECTED_FIREWALL_ROLE"
    info "Firewall role detection: ${role}"
    record_status "firewall_role" "INFO" "${role}"
    if command -v ufw >/dev/null 2>&1; then
        ufw status verbose > "${EVIDENCE_DIR}/ufw-check.txt" 2>&1 || true
        if grep -q 'Status: active' "${EVIDENCE_DIR}/ufw-check.txt"; then
            pass "UFW is active."
            record_status "ufw_check" "PASS" "active"
        else
            warn "UFW is inactive. AWS Security Groups may still filter traffic, but host enforcement is not active."
            record_status "ufw_check" "WARN" "inactive"
        fi
    else
        warn "UFW is not installed."
        record_status "ufw_check" "WARN" "not installed"
    fi
}

check_services() {
    info "Capturing complete enabled/running service inventory plus review candidates. No service is changed by this check."
    local all_out="${EVIDENCE_DIR}/service-inventory-all.txt"
    local cand_out="${EVIDENCE_DIR}/service-review-candidates.tsv"

    {
        echo "# ALL ENABLED SERVICE UNIT FILES"
        systemctl list-unit-files --type=service --state=enabled --no-pager || true
        echo
        echo "# ALL RUNNING SERVICES"
        systemctl list-units --type=service --state=running --no-pager || true
    } > "$all_out"

    printf 'Service\tEnabledState\tActiveState\tUnitFile\tClassification\tAction\n' > "$cand_out"
    local svc enabled active fragment
    for svc in ModemManager.service multipathd.service open-iscsi.service open-vm-tools.service udisks2.service fwupd.service apport.service snapd.service amazon-ssm-agent.service; do
        if systemctl list-unit-files "$svc" --no-legend 2>/dev/null | grep -q .; then
            enabled="$(systemctl is-enabled "$svc" 2>/dev/null || true)"
            active="$(systemctl is-active "$svc" 2>/dev/null || true)"
            fragment="$(systemctl show -p FragmentPath --value "$svc" 2>/dev/null || true)"
            printf '%s\t%s\t%s\t%s\tREVIEW_ON_ACTUAL_MTA\tDO_NOT_AUTO_REMOVE\n' \
                "$svc" "$enabled" "$active" "$fragment" >> "$cand_out"
        fi
    done

    info "Service inventory: ${all_out}"
    info "Service review worksheet: ${cand_out}"
    record_status "service_review" "INFO" "inventory + candidate worksheet captured; classify on actual MTA"
}

check_filesystem_manual_controls() {
    info "Checking mount controls that require manual/build-time decision."
    local out="${EVIDENCE_DIR}/mount-review.txt"
    {
        echo "# /tmp, /dev/shm and key mount review"
        findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS /tmp 2>/dev/null || echo "/tmp: not a separate mount"
        findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS /dev/shm 2>/dev/null || true
        findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS /var 2>/dev/null || echo "/var: not a separate mount"
        findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS /var/log 2>/dev/null || echo "/var/log: not a separate mount"
        findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS /var/log/audit 2>/dev/null || echo "/var/log/audit: not a separate mount"
        findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS /home 2>/dev/null || echo "/home: not a separate mount"
        echo
        echo "03 does not repartition/remount a running production MTA automatically."
    } > "$out"
    record_status "mount_layout" "INFO" "manual/build-time control; ${out}"
}

check_updates() {
    info "Checking available updates and separating security-pocket updates from ordinary upgrades."
    local raw="${EVIDENCE_DIR}/updates-check.txt"
    local tsv="${EVIDENCE_DIR}/updates-classified.tsv"
    classify_updates "$raw" "$tsv"

    local total security standard other
    total="$(awk -F'\t' 'NR>1 {c++} END{print c+0}' "$tsv")"
    security="$(awk -F'\t' 'NR>1 && $6=="SECURITY_POCKET" {c++} END{print c+0}' "$tsv")"
    standard="$(awk -F'\t' 'NR>1 && $6=="STANDARD_UPDATE" {c++} END{print c+0}' "$tsv")"
    other="$(awk -F'\t' 'NR>1 && $6!="SECURITY_POCKET" && $6!="STANDARD_UPDATE" {c++} END{print c+0}' "$tsv")"

    if (( total == 0 )); then
        pass "No upgradeable packages reported by current APT metadata."
        record_status "updates_check" "PASS" "0 upgradeable"
    else
        warn "${total} package(s) are upgradeable: security-pocket=${security}, standard=${standard}, other=${other}."
        info "IMPORTANT: upgradeable package count is NOT treated as a vulnerability count."
        info "See ${tsv} for package-by-package classification."
        record_status "updates_check" "WARN" "total=${total}; security-pocket=${security}; standard=${standard}; other=${other}"
    fi
}

run_checks() {
    info "=== VALIDATION / CHECK PHASE ==="
    check_01_invariants
    check_sysctl
    check_pam
    check_firewall
    write_aws_sg_guidance
    check_services
    check_filesystem_manual_controls
    check_updates

    systemctl --failed --no-legend > "${EVIDENCE_DIR}/failed-units.txt" 2>&1 || true
    ss -lntup > "${EVIDENCE_DIR}/listening-ports.txt" 2>&1 || true
    aa-status > "${EVIDENCE_DIR}/apparmor-status.txt" 2>&1 || true
    visudo -c > "${EVIDENCE_DIR}/visudo-validation.txt" 2>&1 || true
}

main() {
    echo "=============================================================================="
    echo " Mobileum MTA - 03 CIS L1-Aligned OS Hardening"
    echo "=============================================================================="
    echo "Host     : ${HOST_SHORT}"
    echo "Run ID   : ${RUN_TS}"
    echo "Evidence : ${EVIDENCE_DIR}"
    echo "Backup   : ${BACKUP_DIR}"
    echo "MTA1     : ${MTA1_IP}"
    echo "MTA2     : ${MTA2_IP}"
    echo "Jumpbox  : ${JUMPBOX_IP}"
    echo

    check_os
    capture_pre_state

    if (( APPLY_SAFE == 1 )); then
        apply_safe
    fi

    if (( APPLY_PAM == 1 )); then
        apply_pam
    fi

    if (( APPLY_FIREWALL == 1 )); then
        configure_firewall
    fi

    if (( INSTALL_SECURITY_UPDATES == 1 )); then
        install_security_updates
    fi

    disable_approved_services
    run_checks

    touch "${EVIDENCE_DIR}/HARDENING-RUN-COMPLETE"
    chmod 0640 "${EVIDENCE_DIR}/HARDENING-RUN-COMPLETE" || true

    echo
    echo "=============================================================================="
    echo "03 execution complete."
    echo "Evidence : ${EVIDENCE_DIR}"
    echo "Backup   : ${BACKUP_DIR}"
    echo "Summary  : ${SUMMARY_FILE}"
    echo
    echo "IMPORTANT:"
    echo "  - If PAM was changed, test sudo/login in a SECOND session before logout."
    echo "  - If UFW was enabled on an MTA, test NEW SSH sessions from the jumpbox and peer MTA before logout."
    echo "  - If UFW was enabled on the jumpbox, test NEW SSH sessions from office/aws-connect before logout."
    echo "  - AWS SG remediation is separate from UFW: split SG-Mobileum-Jumpbox from SG-Mobileum-MTA."
    echo "  - Do not reboot merely because this script completed."
    echo "  - Run 04 post-hardening assessment only after all selected 03 modules pass."
    echo "=============================================================================="
}

main "$@"
