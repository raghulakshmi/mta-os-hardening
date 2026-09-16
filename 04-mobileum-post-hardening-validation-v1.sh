#!/usr/bin/env bash
# ==============================================================================
# Mobileum Internet-Facing MTA - 04 Post-Hardening Validation
# File    : 04-mobileum-post-hardening-validation-v1.sh
# Version : 1.0
# Target  : Ubuntu Server 24.04 LTS on AWS EC2
# Scope   : READ-ONLY validation of OS hardening applied by stages 01-03.
#
# PURPOSE
# -------
# 1. Validate that the 01 logging/audit foundation remains healthy.
# 2. Validate the selected 03 CIS L1-aligned OS hardening controls.
# 3. Capture a timestamped post-hardening evidence set.
# 4. Compare key post-hardening values against the latest completed 02
#    pre-hardening evidence set for the same host, when available.
# 5. Produce a concise PASS/WARN/FAIL result suitable for change evidence.
#
# IMPORTANT
# ---------
# * This script is READ-ONLY. It does not remediate, install, remove, enable,
#   disable, reload, restart, or reconfigure anything.
# * Exim/application hardening is OUT OF SCOPE and is validated separately.
# * TCP/25 is therefore NOT required to be listening for this script to pass.
# * SSH daemon hardening is not changed/assessed as a CIS completion gate here.
# * AWS rp_filter=2 is a documented Mobileum project exception and is not a
#   failure. A different value is reported for review.
# * Ordinary non-security Ubuntu upgrades are informational/warning evidence,
#   not treated as vulnerabilities or an automatic hardening failure.
# * Mount/repartition controls are build-time/manual controls and are evidence
#   only; this script does not fail because /var, /tmp, /home etc. are not
#   separate filesystems.
#
# USAGE
# -----
#   sudo bash 04-mobileum-post-hardening-validation-v1.sh
#
# Optional explicit evidence paths:
#   sudo bash 04-mobileum-post-hardening-validation-v1.sh \
#       --pre-dir /var/log/mobileum-security/pre-hardening/mta1-<timestamp> \
#       --hardening-dir /var/log/mobileum-security/hardening/mta1-<timestamp>
#
# OUTPUT
# ------
#   /var/log/mobileum-security/post-hardening/<host>-<timestamp>/
#
# Exit codes:
#   0 = completed with PASS and/or WARN only
#   2 = one or more hardening validation failures
# ============================================================================== 

set -Eeuo pipefail
IFS=$'\n\t'
umask 027

SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="1.0"
RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
HOST_SHORT="$(hostname -s 2>/dev/null || hostname)"

POST_ROOT="/var/log/mobileum-security/post-hardening"
OUT="${POST_ROOT}/${HOST_SHORT}-${RUN_TS}"
RUN_LOG="${OUT}/04-post-hardening-run.log"
SUMMARY="${OUT}/POST-HARDENING-SUMMARY.txt"
STATUS_TSV="${OUT}/CONTROL-STATUS.tsv"
COMPARE_TSV="${OUT}/PRE-POST-COMPARISON.tsv"
COMPLETE_MARKER="${OUT}/POST-HARDENING-COMPLETE"
RESULT_FILE="${OUT}/FINAL-RESULT.txt"

PRE_ROOT="/var/log/mobileum-security/pre-hardening"
HARDENING_ROOT="/var/log/mobileum-security/hardening"
PRE_DIR=""
HARDENING_DIR=""
FORCE_OS=0

# Mobileum approved network identity map (2026-09-16)
MTA1_IP="172.31.27.243"
MTA2_IP="172.31.28.75"
JUMPBOX_IP="172.31.25.209"
OFFICE_PUBLIC_IP="45.119.114.19"
AWS_CONNECT_PUBLIC_IP="52.22.247.175"

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
INFO_COUNT=0
FINAL_RESULT="PASS"
DETECTED_ROLE="unknown"

usage() {
    cat <<'USAGE'
Usage:
  sudo bash 04-mobileum-post-hardening-validation-v1.sh [options]

Options:
  --pre-dir DIR         Explicit completed 02 pre-hardening evidence directory.
                        Default: auto-discover latest completed directory for host.
  --hardening-dir DIR   Explicit 03 hardening evidence directory.
                        Default: auto-discover latest directory for host.
  --force-os            Permit validation when OS is not detected as Ubuntu 24.04.
  -h, --help            Show this help.

This script is read-only and excludes Exim/application hardening.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --pre-dir)
            [[ $# -ge 2 ]] || { echo "ERROR: --pre-dir requires a directory" >&2; exit 2; }
            PRE_DIR="$2"; shift ;;
        --hardening-dir)
            [[ $# -ge 2 ]] || { echo "ERROR: --hardening-dir requires a directory" >&2; exit 2; }
            HARDENING_DIR="$2"; shift ;;
        --force-os) FORCE_OS=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: Unknown option: $1" >&2; usage; exit 2 ;;
    esac
    shift
done

if [[ ${EUID} -ne 0 ]]; then
    echo "ERROR: Run as root, for example: sudo bash ${SCRIPT_NAME}" >&2
    exit 1
fi

mkdir -p "$OUT"
chmod 0700 "$OUT"
: > "$STATUS_TSV"
printf 'Control\tResult\tDetail\n' >> "$STATUS_TSV"
: > "$COMPARE_TSV"
printf 'Control\tPre-Hardening\tPost-Hardening\tAssessment\n' >> "$COMPARE_TSV"

exec > >(tee -a "$RUN_LOG") 2>&1

log()  { printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
info() { INFO_COUNT=$((INFO_COUNT+1)); log "INFO  $*"; }
pass() { PASS_COUNT=$((PASS_COUNT+1)); log "PASS  $*"; }
warn() { WARN_COUNT=$((WARN_COUNT+1)); log "WARN  $*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT+1)); log "FAIL  $*"; }

record_status() {
    local control="$1" result="$2" detail="$3"
    detail="${detail//$'\t'/ }"
    detail="${detail//$'\n'/ }"
    printf '%s\t%s\t%s\n' "$control" "$result" "$detail" >> "$STATUS_TSV"
}

record_compare() {
    local control="$1" pre="$2" post="$3" assessment="$4"
    pre="${pre//$'\t'/ }"; pre="${pre//$'\n'/ }"
    post="${post//$'\t'/ }"; post="${post//$'\n'/ }"
    printf '%s\t%s\t%s\t%s\n' "$control" "$pre" "$post" "$assessment" >> "$COMPARE_TSV"
}

capture() {
    local file="$1"; shift
    (
        set +e
        printf '# Captured: %s\n# Command:' "$(date --iso-8601=seconds)"
        printf ' %q' "$@"
        printf '\n\n'
        "$@"
        rc=$?
        printf '\n# Exit status: %s\n' "$rc"
        exit 0
    ) > "${OUT}/${file}" 2>&1
}

capture_shell() {
    local file="$1"; shift
    (
        set +e
        printf '# Captured: %s\n\n' "$(date --iso-8601=seconds)"
        bash -c "$*"
        rc=$?
        printf '\n# Exit status: %s\n' "$rc"
        exit 0
    ) > "${OUT}/${file}" 2>&1
}

have() { command -v "$1" >/dev/null 2>&1; }

latest_dir() {
    local root="$1" host="$2"
    find "$root" -mindepth 1 -maxdepth 1 -type d -name "${host}-*" -print 2>/dev/null | sort | tail -1
}

latest_completed_pre_dir() {
    local root="$1" host="$2"
    local d
    while IFS= read -r d; do
        [[ -f "${d}/ASSESSMENT-COMPLETE" ]] && { printf '%s\n' "$d"; return 0; }
    done < <(find "$root" -mindepth 1 -maxdepth 1 -type d -name "${host}-*" -print 2>/dev/null | sort -r)
    return 1
}

on_error() {
    local rc=$? line="$1"
    fail "Unexpected runtime error at line ${line}; rc=${rc}."
    record_status "script_runtime" "FAIL" "line=${line}; rc=${rc}"
    write_summary || true
    exit "$rc"
}
trap 'on_error $LINENO' ERR

write_summary() {
    if (( FAIL_COUNT > 0 )); then
        FINAL_RESULT="FAIL"
    elif (( WARN_COUNT > 0 )); then
        FINAL_RESULT="PASS_WITH_WARNINGS"
    else
        FINAL_RESULT="PASS"
    fi

    {
        echo "=============================================================================="
        echo " MOBILEUM MTA - 04 POST-HARDENING VALIDATION SUMMARY"
        echo "=============================================================================="
        echo
        echo "Host             : ${HOST_SHORT}"
        echo "UTC Run ID       : ${RUN_TS}"
        echo "Script           : ${SCRIPT_NAME} v${SCRIPT_VERSION}"
        echo "Mode             : READ-ONLY"
        echo "Scope            : OS/host hardening stages 01-03; Exim excluded"
        echo "Detected role    : ${DETECTED_ROLE}"
        echo "Pre evidence     : ${PRE_DIR:-NOT FOUND}"
        echo "03 evidence      : ${HARDENING_DIR:-NOT FOUND}"
        echo "Post evidence    : ${OUT}"
        echo
        echo "Result           : ${FINAL_RESULT}"
        echo "PASS             : ${PASS_COUNT}"
        echo "WARN             : ${WARN_COUNT}"
        echo "FAIL             : ${FAIL_COUNT}"
        echo "INFO             : ${INFO_COUNT}"
        echo
        echo "Important interpretation:"
        echo "  - Exim is not part of this validation. TCP/25 does not need to be listening."
        echo "  - Standard/non-security package upgrades are not vulnerability counts."
        echo "  - rp_filter=2 is the documented AWS project exception."
        echo "  - Mount/repartition controls are build-time/manual controls."
        echo "  - A fresh SSH login test from the jumpbox remains an operational check;"
        echo "    this script can validate the current session source and UFW rules but"
        echo "    cannot create an independent administrator login session for you."
        echo
        echo "Evidence files:"
        echo "  ${STATUS_TSV}"
        echo "  ${COMPARE_TSV}"
        echo "  ${RUN_LOG}"
    } > "$SUMMARY"

    printf '%s\n' "$FINAL_RESULT" > "$RESULT_FILE"
    {
        echo "completed_utc=${RUN_TS}"
        echo "result=${FINAL_RESULT}"
        echo "pass=${PASS_COUNT}"
        echo "warn=${WARN_COUNT}"
        echo "fail=${FAIL_COUNT}"
        echo "pre_dir=${PRE_DIR:-NOT_FOUND}"
        echo "hardening_dir=${HARDENING_DIR:-NOT_FOUND}"
        echo "post_dir=${OUT}"
    } > "$COMPLETE_MARKER"
    chmod 0600 "$SUMMARY" "$RESULT_FILE" "$COMPLETE_MARKER" "$STATUS_TSV" "$COMPARE_TSV" 2>/dev/null || true
}
trap write_summary EXIT

check_os() {
    info "Checking operating system and host identity."
    capture "01-system-info.txt" bash -c 'cat /etc/os-release; echo; hostnamectl 2>/dev/null || true; echo; uname -a; echo; ip -brief address 2>/dev/null || true'

    local id="" version=""
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        id="${ID:-}"
        version="${VERSION_ID:-}"
    fi

    if [[ "$id" == "ubuntu" && "$version" == "24.04" ]]; then
        pass "Ubuntu 24.04 detected."
        record_status "os" "PASS" "Ubuntu 24.04"
    elif (( FORCE_OS == 1 )); then
        warn "OS is ${id:-unknown} ${version:-unknown}; continuing because --force-os was supplied."
        record_status "os" "WARN" "forced: ${id:-unknown} ${version:-unknown}"
    else
        fail "Expected Ubuntu 24.04; detected ${id:-unknown} ${version:-unknown}."
        record_status "os" "FAIL" "detected ${id:-unknown} ${version:-unknown}"
    fi
}

discover_source_evidence() {
    info "Locating 02 pre-hardening and 03 hardening evidence."

    if [[ -n "$PRE_DIR" ]]; then
        if [[ -d "$PRE_DIR" && -f "$PRE_DIR/ASSESSMENT-COMPLETE" ]]; then
            pass "Explicit completed 02 pre-hardening evidence found: ${PRE_DIR}"
            record_status "pre_evidence" "PASS" "$PRE_DIR"
        else
            warn "Explicit --pre-dir is not a completed 02 evidence directory: ${PRE_DIR}"
            record_status "pre_evidence" "WARN" "$PRE_DIR"
        fi
    else
        PRE_DIR="$(latest_completed_pre_dir "$PRE_ROOT" "$HOST_SHORT" 2>/dev/null || true)"
        if [[ -n "$PRE_DIR" ]]; then
            pass "Latest completed 02 pre-hardening evidence: ${PRE_DIR}"
            record_status "pre_evidence" "PASS" "$PRE_DIR"
        else
            warn "No completed 02 pre-hardening evidence found for ${HOST_SHORT}; post validation will continue without PRE comparison."
            record_status "pre_evidence" "WARN" "not found"
        fi
    fi

    if [[ -n "$HARDENING_DIR" ]]; then
        if [[ -d "$HARDENING_DIR" ]]; then
            pass "Explicit 03 hardening evidence found: ${HARDENING_DIR}"
            record_status "hardening_evidence" "PASS" "$HARDENING_DIR"
        else
            warn "Explicit --hardening-dir does not exist: ${HARDENING_DIR}"
            record_status "hardening_evidence" "WARN" "$HARDENING_DIR"
        fi
    else
        HARDENING_DIR="$(latest_dir "$HARDENING_ROOT" "$HOST_SHORT" 2>/dev/null || true)"
        if [[ -n "$HARDENING_DIR" ]]; then
            pass "Latest 03 hardening evidence: ${HARDENING_DIR}"
            record_status "hardening_evidence" "PASS" "$HARDENING_DIR"
        else
            warn "No 03 hardening evidence directory found for ${HOST_SHORT}."
            record_status "hardening_evidence" "WARN" "not found"
        fi
    fi
}

detect_role() {
    local ips
    ips="$(hostname -I 2>/dev/null || true)"
    if [[ " $ips " == *" ${MTA1_IP} "* ]] || [[ "$HOST_SHORT" == "mta1" || "$HOST_SHORT" == "mta1.mobileum.com" ]]; then
        DETECTED_ROLE="mta1"
    elif [[ " $ips " == *" ${MTA2_IP} "* ]] || [[ "$HOST_SHORT" == "mta2" || "$HOST_SHORT" == "mta2.mobileum.com" ]]; then
        DETECTED_ROLE="mta2"
    elif [[ " $ips " == *" ${JUMPBOX_IP} "* ]] || [[ "$HOST_SHORT" == *jump* ]]; then
        DETECTED_ROLE="jumpbox"
    else
        DETECTED_ROLE="unknown"
    fi
    info "Detected host role: ${DETECTED_ROLE}"
    record_status "host_role" "INFO" "$DETECTED_ROLE"
}

check_logging_audit() {
    info "Validating 01 logging/audit foundation."
    capture_shell "02-logging-audit-status.txt" '
for s in systemd-journald rsyslog auditd; do
  printf "%s active=" "$s"; systemctl is-active "$s" 2>/dev/null || true
  printf "%s enabled=" "$s"; systemctl is-enabled "$s" 2>/dev/null || true
done
echo
command -v auditctl >/dev/null 2>&1 && auditctl -s || true
echo
command -v auditctl >/dev/null 2>&1 && auditctl -l || true
echo
journalctl --disk-usage 2>/dev/null || true
'

    local svc
    for svc in systemd-journald rsyslog auditd; do
        if systemctl is-active --quiet "$svc"; then
            pass "${svc} is active."
            record_status "service:${svc}" "PASS" "active"
        else
            fail "${svc} is not active."
            record_status "service:${svc}" "FAIL" "inactive"
        fi
    done

    if have auditctl; then
        local enabled lost backlog
        enabled="$(auditctl -s 2>/dev/null | awk '$1=="enabled"{print $2; exit}')"
        lost="$(auditctl -s 2>/dev/null | awk '$1=="lost"{print $2; exit}')"
        backlog="$(auditctl -s 2>/dev/null | awk '$1=="backlog"{print $2; exit}')"
        if [[ "$enabled" == "1" && "$lost" == "0" ]]; then
            pass "auditd runtime healthy and mutable: enabled=1, lost=0."
            record_status "audit_runtime" "PASS" "enabled=1 lost=0 backlog=${backlog:-?}"
        else
            fail "auditd runtime differs from project baseline: enabled=${enabled:-?}, lost=${lost:-?}."
            record_status "audit_runtime" "FAIL" "enabled=${enabled:-?} lost=${lost:-?} backlog=${backlog:-?}"
        fi
    else
        fail "auditctl is missing."
        record_status "audit_runtime" "FAIL" "auditctl missing"
    fi

    if [[ -d /var/log/journal ]]; then
        pass "Persistent journal directory exists: /var/log/journal."
        record_status "persistent_journal" "PASS" "/var/log/journal"
    else
        fail "Persistent journal directory /var/log/journal is missing."
        record_status "persistent_journal" "FAIL" "missing"
    fi

    if [[ -f /etc/systemd/journald.conf.d/10-mta-logging.conf ]] &&
       grep -Eq '^[[:space:]]*ForwardToSyslog[[:space:]]*=[[:space:]]*yes' /etc/systemd/journald.conf.d/10-mta-logging.conf; then
        pass "Mobileum journald configuration and ForwardToSyslog=yes are present."
        record_status "journald_config" "PASS" "ForwardToSyslog=yes"
    else
        fail "Expected Mobileum journald configuration/ForwardToSyslog=yes not found."
        record_status "journald_config" "FAIL" "missing or changed"
    fi

    local f
    for f in /var/log/sudo.log /etc/profile.d/mta-history.sh /etc/sudoers.d/mta-audit /etc/audit/rules.d/99-mobileum-logging.rules; do
        if [[ -e "$f" ]]; then
            pass "Required 01 artifact present: ${f}"
            record_status "artifact:${f}" "PASS" "present"
        else
            fail "Required 01 artifact missing: ${f}"
            record_status "artifact:${f}" "FAIL" "missing"
        fi
    done

    if [[ -d /var/log/sudo-io ]]; then
        pass "sudo I/O log directory exists."
        record_status "sudo_io" "PASS" "/var/log/sudo-io"
    else
        fail "sudo I/O log directory /var/log/sudo-io is missing."
        record_status "sudo_io" "FAIL" "missing"
    fi
}

check_sysctl() {
    info "Validating 03 network/kernel hardening values."
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

    printf 'Key\tCurrent\tTarget\tResult\n' > "${OUT}/03-sysctl-validation.tsv"
    local key got want
    for key in "${!expected[@]}"; do
        want="${expected[$key]}"
        if [[ ! -e "/proc/sys/${key//./\/}" ]]; then
            warn "${key} is not available on this kernel."
            record_status "sysctl:${key}" "WARN" "not available; target=${want}"
            printf '%s\tN/A\t%s\tWARN\n' "$key" "$want" >> "${OUT}/03-sysctl-validation.tsv"
            continue
        fi
        got="$(sysctl -n "$key" 2>/dev/null || echo '?')"
        if [[ "$got" == "$want" ]]; then
            pass "${key}=${got}"
            record_status "sysctl:${key}" "PASS" "$got"
            printf '%s\t%s\t%s\tPASS\n' "$key" "$got" "$want" >> "${OUT}/03-sysctl-validation.tsv"
        else
            fail "${key}=${got}; required=${want}"
            record_status "sysctl:${key}" "FAIL" "current=${got}; target=${want}"
            printf '%s\t%s\t%s\tFAIL\n' "$key" "$got" "$want" >> "${OUT}/03-sysctl-validation.tsv"
        fi
    done

    local rp_all rp_def
    rp_all="$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo N/A)"
    rp_def="$(sysctl -n net.ipv4.conf.default.rp_filter 2>/dev/null || echo N/A)"
    if [[ "$rp_all" == "2" && "$rp_def" == "2" ]]; then
        pass "AWS project exception preserved: rp_filter all=2, default=2."
        record_status "rp_filter_exception" "PASS" "all=2 default=2"
    else
        warn "AWS rp_filter project exception differs: all=${rp_all}, default=${rp_def}; review before changing."
        record_status "rp_filter_exception" "WARN" "all=${rp_all} default=${rp_def}"
    fi
}

check_permissions() {
    info "Validating critical identity, cron, and sudo permissions."
    printf 'Path\tMode\tOwner\tGroup\tExpected\tResult\n' > "${OUT}/04-permissions-validation.tsv"

    check_one_permission() {
        local path="$1" exp_mode="$2" exp_owner="$3" exp_group="$4"
        if [[ ! -e "$path" ]]; then
            warn "Expected path not found: ${path}"
            record_status "permission:${path}" "WARN" "missing"
            printf '%s\tMISSING\t-\t-\t%s %s:%s\tWARN\n' "$path" "$exp_mode" "$exp_owner" "$exp_group" >> "${OUT}/04-permissions-validation.tsv"
            return
        fi
        local mode owner group
        mode="$(stat -c '%a' "$path")"
        owner="$(stat -c '%U' "$path")"
        group="$(stat -c '%G' "$path")"
        if [[ "$mode" == "$exp_mode" && "$owner" == "$exp_owner" && "$group" == "$exp_group" ]]; then
            pass "${path}: ${mode} ${owner}:${group}"
            record_status "permission:${path}" "PASS" "${mode} ${owner}:${group}"
            printf '%s\t%s\t%s\t%s\t%s %s:%s\tPASS\n' "$path" "$mode" "$owner" "$group" "$exp_mode" "$exp_owner" "$exp_group" >> "${OUT}/04-permissions-validation.tsv"
        else
            fail "${path}: ${mode} ${owner}:${group}; required ${exp_mode} ${exp_owner}:${exp_group}"
            record_status "permission:${path}" "FAIL" "${mode} ${owner}:${group}; target=${exp_mode} ${exp_owner}:${exp_group}"
            printf '%s\t%s\t%s\t%s\t%s %s:%s\tFAIL\n' "$path" "$mode" "$owner" "$group" "$exp_mode" "$exp_owner" "$exp_group" >> "${OUT}/04-permissions-validation.tsv"
        fi
    }

    check_one_permission /etc/passwd 644 root root
    check_one_permission /etc/group 644 root root
    check_one_permission /etc/shadow 640 root shadow
    check_one_permission /etc/gshadow 640 root shadow
    check_one_permission /etc/crontab 600 root root

    local d
    for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        [[ -e "$d" ]] && check_one_permission "$d" 700 root root
    done

    if have visudo && visudo -cf /etc/sudoers > "${OUT}/05-visudo-validation.txt" 2>&1; then
        pass "sudoers syntax validation passed."
        record_status "sudoers_syntax" "PASS" "visudo -c"
    else
        fail "sudoers syntax validation failed."
        record_status "sudoers_syntax" "FAIL" "see 05-visudo-validation.txt"
    fi

    if [[ -f /etc/sudoers.d/91-mobileum-cis-l1 ]] && grep -Eq '^[[:space:]]*Defaults[[:space:]]+timestamp_timeout=15' /etc/sudoers.d/91-mobileum-cis-l1; then
        pass "sudo timestamp_timeout=15 project policy present."
        record_status "sudo_timeout" "PASS" "15 minutes"
    else
        fail "sudo timestamp_timeout=15 project policy not detected."
        record_status "sudo_timeout" "FAIL" "missing/changed"
    fi
}

check_apparmor() {
    info "Validating AppArmor."
    capture "06-apparmor-status.txt" aa-status
    if systemctl is-active --quiet apparmor.service; then
        pass "AppArmor service is active."
        record_status "apparmor" "PASS" "active"
    else
        fail "AppArmor service is not active."
        record_status "apparmor" "FAIL" "inactive"
    fi
}

get_cfg_value() {
    local file="$1" key="$2"
    [[ -f "$file" ]] || return 1
    awk -F= -v k="$key" '
      $0 !~ /^[[:space:]]*#/ {
        left=$1; gsub(/^[[:space:]]+|[[:space:]]+$/, "", left)
        if (left==k) { val=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", val); print val; exit }
      }' "$file"
}

check_pam() {
    info "Validating PAM/password/account controls."
    capture_shell "07-pam-state.txt" '
echo "### common-auth"; cat /etc/pam.d/common-auth 2>/dev/null || true
echo; echo "### common-account"; cat /etc/pam.d/common-account 2>/dev/null || true
echo; echo "### common-password"; cat /etc/pam.d/common-password 2>/dev/null || true
echo; echo "### faillock.conf"; cat /etc/security/faillock.conf 2>/dev/null || true
echo; echo "### pwquality Mobileum"; cat /etc/security/pwquality.conf.d/50-mobileum.conf 2>/dev/null || true
echo; echo "### pwhistory.conf"; cat /etc/security/pwhistory.conf 2>/dev/null || true
'

    local pam_ok=1 pwq_count
    grep -Eq 'pam_faillock\.so' /etc/pam.d/common-auth 2>/dev/null || pam_ok=0
    grep -Eq 'pam_faillock\.so' /etc/pam.d/common-account 2>/dev/null || pam_ok=0
    pwq_count="$(grep -Ec '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' /etc/pam.d/common-password 2>/dev/null || true)"
    [[ "$pwq_count" == "1" ]] || pam_ok=0
    grep -Eq 'pam_pwhistory\.so' /etc/pam.d/common-password 2>/dev/null || pam_ok=0
    if grep -Eq 'pam_unix\.so.*\bnullok\b' /etc/pam.d/common-auth /etc/pam.d/common-password 2>/dev/null; then pam_ok=0; fi
    grep -Eq '^password[[:space:]].*pam_unix\.so.*\buse_authtok\b' /etc/pam.d/common-password 2>/dev/null || pam_ok=0
    grep -Eq '^password[[:space:]].*pam_unix\.so.*\b(yescrypt|sha512)\b' /etc/pam.d/common-password 2>/dev/null || pam_ok=0

    if (( pam_ok == 1 )); then
        pass "PAM stack baseline passed; exactly one pwquality module detected."
        record_status "pam_stack" "PASS" "faillock/single-pwquality/pwhistory; nullok absent; strong pam_unix"
    else
        fail "PAM stack baseline failed."
        record_status "pam_stack" "FAIL" "see 07-pam-state.txt; pwquality_count=${pwq_count}"
    fi

    local deny interval unlock root_unlock
    deny="$(get_cfg_value /etc/security/faillock.conf deny 2>/dev/null || true)"
    interval="$(get_cfg_value /etc/security/faillock.conf fail_interval 2>/dev/null || true)"
    unlock="$(get_cfg_value /etc/security/faillock.conf unlock_time 2>/dev/null || true)"
    root_unlock="$(get_cfg_value /etc/security/faillock.conf root_unlock_time 2>/dev/null || true)"
    if [[ "$deny" == "5" && "$interval" == "900" && "$unlock" == "900" && "$root_unlock" == "900" ]] && grep -Eq '^[[:space:]]*even_deny_root([[:space:]]|$)' /etc/security/faillock.conf 2>/dev/null; then
        pass "faillock policy matches Mobileum baseline."
        record_status "faillock_policy" "PASS" "deny=5 interval=900 unlock=900 root_unlock=900 even_deny_root"
    else
        fail "faillock policy differs from Mobileum baseline."
        record_status "faillock_policy" "FAIL" "deny=${deny:-?} interval=${interval:-?} unlock=${unlock:-?} root_unlock=${root_unlock:-?}"
    fi

    local qfile="/etc/security/pwquality.conf.d/50-mobileum.conf"
    local q_ok=1 key value expected
    while IFS='=' read -r key expected; do
        value="$(get_cfg_value "$qfile" "$key" 2>/dev/null || true)"
        [[ "$value" == "$expected" ]] || q_ok=0
    done <<'POLICY'
minlen=14
difok=2
dcredit=-1
ucredit=-1
lcredit=-1
ocredit=-1
maxrepeat=3
maxsequence=3
gecoscheck=1
dictcheck=1
usercheck=1
enforcing=1
retry=3
POLICY
    grep -Eq '^[[:space:]]*enforce_for_root([[:space:]]|$)' "$qfile" 2>/dev/null || q_ok=0
    if (( q_ok == 1 )); then
        pass "pwquality policy matches Mobileum baseline."
        record_status "pwquality_policy" "PASS" "minlen=14; class requirements; enforcing; enforce_for_root"
    else
        fail "pwquality policy differs from Mobileum baseline."
        record_status "pwquality_policy" "FAIL" "$qfile"
    fi

    if [[ "$(get_cfg_value /etc/security/pwhistory.conf remember 2>/dev/null || true)" == "24" ]] && grep -Eq '^[[:space:]]*enforce_for_root([[:space:]]|$)' /etc/security/pwhistory.conf 2>/dev/null; then
        pass "pwhistory policy matches Mobileum baseline (remember=24)."
        record_status "pwhistory_policy" "PASS" "remember=24 enforce_for_root"
    else
        fail "pwhistory policy differs from Mobileum baseline."
        record_status "pwhistory_policy" "FAIL" "expected remember=24 enforce_for_root"
    fi

    printf 'user\tpasswd_state\tmin_days\tmax_days\twarn_days\tassessment\n' > "${OUT}/08-account-aging-review.tsv"
    local user uid shell state mind maxd warnd assessment
    while IFS=: read -r user _ uid _ _ _ shell; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        (( uid == 0 || uid >= 1000 )) || continue
        case "$shell" in */nologin|*/false) continue ;; esac
        state="$(passwd -S "$user" 2>/dev/null | awk '{print $2}' || echo UNKNOWN)"
        mind="$(chage -l "$user" 2>/dev/null | awk -F: '/Minimum number of days/{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}')"
        maxd="$(chage -l "$user" 2>/dev/null | awk -F: '/Maximum number of days/{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}')"
        warnd="$(chage -l "$user" 2>/dev/null | awk -F: '/Number of days of warning/{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}')"
        if [[ "$state" == "L" || "$state" == "LK" ]]; then
            assessment="EXCEPTION_PASSWORD_LOCKED_KEY_BASED"
        elif [[ "$mind" == "1" && "$maxd" == "365" && "$warnd" == "7" ]]; then
            assessment="PASS"
        else
            assessment="REVIEW"
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$user" "$state" "$mind" "$maxd" "$warnd" "$assessment" >> "${OUT}/08-account-aging-review.tsv"
    done < <(getent passwd)

    if awk -F'\t' 'NR>1 && $6=="REVIEW" {found=1} END{exit(found?0:1)}' "${OUT}/08-account-aging-review.tsv"; then
        warn "One or more interactive accounts require password-aging review."
        record_status "account_aging" "WARN" "see 08-account-aging-review.tsv"
    else
        pass "Interactive accounts are either policy-compliant or explicitly password-locked/key-based exceptions."
        record_status "account_aging" "PASS" "see 08-account-aging-review.tsv"
    fi
}

check_firewall() {
    info "Validating host firewall policy."
    if ! have ufw; then
        fail "UFW is not installed."
        record_status "ufw" "FAIL" "not installed"
        return
    fi

    ufw status verbose > "${OUT}/09-ufw-status.txt" 2>&1 || true
    ufw status numbered > "${OUT}/09-ufw-numbered.txt" 2>&1 || true

    if ! grep -q 'Status: active' "${OUT}/09-ufw-status.txt"; then
        fail "UFW is inactive."
        record_status "ufw" "FAIL" "inactive"
        return
    fi
    pass "UFW is active."
    record_status "ufw" "PASS" "active"

    if grep -Eq '^Default:[[:space:]]+deny \(incoming\), allow \(outgoing\)' "${OUT}/09-ufw-status.txt"; then
        pass "UFW default policy is deny incoming / allow outgoing."
        record_status "ufw_default" "PASS" "deny incoming; allow outgoing"
    else
        fail "UFW default policy differs from deny incoming / allow outgoing."
        record_status "ufw_default" "FAIL" "see 09-ufw-status.txt"
    fi

    local rules="${OUT}/09-ufw-numbered.txt"
    case "$DETECTED_ROLE" in
        mta1)
            grep -Eq '22/tcp.*ALLOW IN.*172\.31\.25\.209' "$rules" && pass "MTA1 SSH allowed from jumpbox." || fail "MTA1 SSH rule from jumpbox missing."
            grep -Eq '22/tcp.*ALLOW IN.*172\.31\.28\.75' "$rules" && pass "MTA1 SSH allowed from MTA2 peer." || fail "MTA1 SSH rule from MTA2 missing."
            grep -Eq '25/tcp.*ALLOW IN.*Anywhere' "$rules" && pass "MTA1 Internet SMTP TCP/25 rule present." || fail "MTA1 Internet SMTP TCP/25 rule missing."
            ;;
        mta2)
            grep -Eq '22/tcp.*ALLOW IN.*172\.31\.25\.209' "$rules" && pass "MTA2 SSH allowed from jumpbox." || fail "MTA2 SSH rule from jumpbox missing."
            grep -Eq '22/tcp.*ALLOW IN.*172\.31\.27\.243' "$rules" && pass "MTA2 SSH allowed from MTA1 peer." || fail "MTA2 SSH rule from MTA1 missing."
            grep -Eq '25/tcp.*ALLOW IN.*Anywhere' "$rules" && pass "MTA2 Internet SMTP TCP/25 rule present." || fail "MTA2 Internet SMTP TCP/25 rule missing."
            ;;
        jumpbox)
            grep -Eq '22/tcp.*ALLOW IN.*45\.119\.114\.19' "$rules" && pass "Jumpbox SSH allowed from DriveIT office." || fail "Jumpbox office SSH rule missing."
            grep -Eq '22/tcp.*ALLOW IN.*52\.22\.247\.175' "$rules" && pass "Jumpbox SSH allowed from aws-connect." || fail "Jumpbox aws-connect SSH rule missing."
            ;;
        *)
            warn "Host role unknown; UFW is active but role-specific rules were not evaluated."
            record_status "ufw_role_rules" "WARN" "unknown role"
            ;;
    esac

    # Record role-rule overall state from current FAIL count change is intentionally
    # left to the individual checks above; detailed rules are preserved in evidence.
}

check_current_admin_path() {
    info "Recording current administrative connection source."
    {
        echo "SSH_CONNECTION=${SSH_CONNECTION:-}"
        echo "SSH_CLIENT=${SSH_CLIENT:-}"
        who -u 2>/dev/null || true
    } > "${OUT}/10-admin-session.txt"

    if [[ -z "${SSH_CONNECTION:-}" ]]; then
        warn "No SSH_CONNECTION is present (possibly console/SSM); fresh jumpbox SSH must be validated manually."
        record_status "admin_path" "WARN" "not an SSH session"
        return
    fi

    local src
    src="${SSH_CONNECTION%% *}"
    case "$DETECTED_ROLE" in
        mta1)
            if [[ "$src" == "$JUMPBOX_IP" || "$src" == "$MTA2_IP" ]]; then
                pass "Current MTA1 SSH session originates from approved source ${src}."
                record_status "admin_path" "PASS" "source=${src}"
            else
                warn "Current MTA1 SSH source ${src} is outside expected jumpbox/peer paths."
                record_status "admin_path" "WARN" "source=${src}"
            fi
            ;;
        mta2)
            if [[ "$src" == "$JUMPBOX_IP" || "$src" == "$MTA1_IP" ]]; then
                pass "Current MTA2 SSH session originates from approved source ${src}."
                record_status "admin_path" "PASS" "source=${src}"
            else
                warn "Current MTA2 SSH source ${src} is outside expected jumpbox/peer paths."
                record_status "admin_path" "WARN" "source=${src}"
            fi
            ;;
        *)
            info "Current SSH source is ${src}; no MTA source assertion applied for role=${DETECTED_ROLE}."
            record_status "admin_path" "INFO" "source=${src}"
            ;;
    esac
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

check_updates() {
    info "Classifying currently visible package upgrades using existing APT metadata (no apt update is run)."
    classify_updates "${OUT}/11-updates-raw.txt" "${OUT}/11-updates-classified.tsv"
    local total security standard other
    total="$(awk -F'\t' 'NR>1 {c++} END{print c+0}' "${OUT}/11-updates-classified.tsv")"
    security="$(awk -F'\t' 'NR>1 && $6=="SECURITY_POCKET" {c++} END{print c+0}' "${OUT}/11-updates-classified.tsv")"
    standard="$(awk -F'\t' 'NR>1 && $6=="STANDARD_UPDATE" {c++} END{print c+0}' "${OUT}/11-updates-classified.tsv")"
    other="$(awk -F'\t' 'NR>1 && $6!="SECURITY_POCKET" && $6!="STANDARD_UPDATE" {c++} END{print c+0}' "${OUT}/11-updates-classified.tsv")"

    if (( security > 0 )); then
        warn "${security} security-pocket update(s) are currently visible; review before final production cutover."
        record_status "updates" "WARN" "total=${total}; security=${security}; standard=${standard}; other=${other}"
    elif (( total > 0 )); then
        warn "No security-pocket updates; ${total} ordinary/other upgrade(s) remain (standard=${standard}, other=${other})."
        record_status "updates" "WARN" "security=0; total=${total}; standard=${standard}; other=${other}"
    else
        pass "No upgradeable packages visible in current APT metadata."
        record_status "updates" "PASS" "0 upgradeable"
    fi

    if [[ -f /var/run/reboot-required ]]; then
        warn "A reboot-required marker exists; do not reboot outside the approved MTA change window."
        record_status "reboot_required" "WARN" "$(tr '\n' ' ' < /var/run/reboot-required 2>/dev/null || true)"
        cp -a /var/run/reboot-required "${OUT}/11-reboot-required.txt" 2>/dev/null || true
        cp -a /var/run/reboot-required.pkgs "${OUT}/11-reboot-required.pkgs.txt" 2>/dev/null || true
    else
        pass "No reboot-required marker is present."
        record_status "reboot_required" "PASS" "none"
    fi
}

check_services_and_runtime() {
    info "Capturing service/runtime state and review candidates."
    capture_shell "12-services-runtime.txt" '
echo "### Failed units"; systemctl --failed --no-pager || true
echo; echo "### Enabled services"; systemctl list-unit-files --type=service --state=enabled --no-pager || true
echo; echo "### Running services"; systemctl list-units --type=service --state=running --no-pager || true
'
    capture "13-listening-ports.txt" ss -lntup

    local failed_count
    failed_count="$(systemctl --failed --no-legend --no-pager 2>/dev/null | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')"
    if [[ "$failed_count" == "0" ]]; then
        pass "No failed systemd units detected."
        record_status "failed_units" "PASS" "0"
    else
        warn "${failed_count} failed systemd unit(s) detected; review 12-services-runtime.txt."
        record_status "failed_units" "WARN" "$failed_count"
    fi

    printf 'Service\tEnabledState\tActiveState\tClassification\tRecommendation\n' > "${OUT}/12-service-review-candidates.tsv"
    local svc enabled active classification recommendation review_count=0
    for svc in ModemManager.service multipathd.service open-iscsi.service open-vm-tools.service udisks2.service fwupd.service apport.service snapd.service amazon-ssm-agent.service; do
        if systemctl list-unit-files "$svc" --no-legend 2>/dev/null | grep -q .; then
            enabled="$(systemctl is-enabled "$svc" 2>/dev/null || true)"
            active="$(systemctl is-active "$svc" 2>/dev/null || true)"
            classification="REVIEW_ON_ACTUAL_MTA"
            recommendation="DO_NOT_AUTO_REMOVE"
            if [[ "$svc" == "amazon-ssm-agent.service" ]]; then
                classification="AWS_MANAGEMENT_RECOVERY"
                recommendation="KEEP_IF_USED_FOR_RECOVERY_OR_MANAGEMENT"
            elif [[ "$svc" == "open-vm-tools.service" ]]; then
                classification="LIKELY_NOT_REQUIRED_ON_AWS_EC2"
                recommendation="REVIEW_BEFORE_DISABLE"
            fi
            printf '%s\t%s\t%s\t%s\t%s\n' "$svc" "$enabled" "$active" "$classification" "$recommendation" >> "${OUT}/12-service-review-candidates.tsv"
            if [[ "$classification" == "REVIEW_ON_ACTUAL_MTA" || "$classification" == "LIKELY_NOT_REQUIRED_ON_AWS_EC2" ]]; then
                review_count=$((review_count+1))
            fi
        fi
    done

    if (( review_count > 0 )); then
        warn "${review_count} service candidate(s) still require explicit operational classification; no service was changed by 04."
        record_status "service_review" "WARN" "${review_count} candidate(s); see 12-service-review-candidates.tsv"
    else
        pass "No generic service-review candidates detected."
        record_status "service_review" "PASS" "no candidates"
    fi

    if ss -lnt 2>/dev/null | grep -Eq '[:.]22[[:space:]]'; then
        pass "SSH TCP/22 is listening."
        record_status "ssh_listener" "PASS" "TCP/22 listening"
    else
        warn "TCP/22 was not detected as listening; this may be expected only for non-SSH management."
        record_status "ssh_listener" "WARN" "not detected"
    fi

    if ss -lnt 2>/dev/null | grep -Eq '[:.]25[[:space:]]'; then
        info "TCP/25 is listening. Exim remains outside 04 validation scope."
        record_status "smtp_listener" "INFO" "TCP/25 listening"
    else
        info "TCP/25 is not listening. This is acceptable before Exim installation/configuration."
        record_status "smtp_listener" "INFO" "not listening; Exim out of scope"
    fi
}

check_mount_evidence() {
    info "Capturing build-time/manual mount controls."
    capture_shell "14-mount-review.txt" '
for p in /tmp /dev/shm /var /var/log /var/log/audit /home; do
  printf "%s: " "$p"
  findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS "$p" 2>/dev/null || echo "not a separate mount"
done
'
    record_status "mount_layout" "INFO" "manual/build-time control; see 14-mount-review.txt"
}

pre_sysctl_value() {
    local key="$1"
    [[ -n "$PRE_DIR" && -f "${PRE_DIR}/14-sysctl-security.txt" ]] || return 1
    awk -F= -v k="$key" '
      index($0,k)==1 {
        v=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); print v; exit
      }' "${PRE_DIR}/14-sysctl-security.txt"
}

compare_pre_post() {
    info "Building PRE vs POST comparison."
    if [[ -z "$PRE_DIR" || ! -d "$PRE_DIR" ]]; then
        warn "PRE vs POST comparison skipped because no completed 02 evidence is available."
        record_status "pre_post_comparison" "WARN" "no pre evidence"
        return
    fi

    local -a keys=(
        net.ipv4.conf.all.accept_redirects
        net.ipv4.conf.default.accept_redirects
        net.ipv4.conf.all.secure_redirects
        net.ipv4.conf.default.secure_redirects
        net.ipv4.conf.all.send_redirects
        net.ipv4.conf.default.send_redirects
        net.ipv4.conf.all.accept_source_route
        net.ipv4.conf.default.accept_source_route
        net.ipv4.conf.all.log_martians
        net.ipv4.conf.default.log_martians
        net.ipv4.tcp_syncookies
        net.ipv6.conf.all.accept_redirects
        net.ipv6.conf.default.accept_redirects
    )
    local key pre post assessment
    for key in "${keys[@]}"; do
        pre="$(pre_sysctl_value "$key" 2>/dev/null || true)"
        post="$(sysctl -n "$key" 2>/dev/null || echo N/A)"
        [[ -n "$pre" ]] || pre="NOT_CAPTURED"
        assessment="CHANGED_OR_VALIDATED"
        [[ "$pre" == "$post" ]] && assessment="UNCHANGED"
        record_compare "$key" "$pre" "$post" "$assessment"
    done

    local pre_fw="NOT_CAPTURED" post_fw="inactive"
    if [[ -f "${PRE_DIR}/11-firewall.txt" ]]; then
        pre_fw="$(grep -m1 -E '^Status:' "${PRE_DIR}/11-firewall.txt" 2>/dev/null | sed 's/^[[:space:]]*//' || true)"
        [[ -n "$pre_fw" ]] || pre_fw="NOT_CAPTURED"
    fi
    if ufw status 2>/dev/null | grep -q 'Status: active'; then post_fw="Status: active"; else post_fw="Status: inactive"; fi
    record_compare "UFW" "$pre_fw" "$post_fw" "POST_VALIDATED"

    local pre_pam="NOT_HARDENED_OR_NOT_CAPTURED" post_pam="HARDENED"
    if [[ -f "${PRE_DIR}/16-pam-password-policy.txt" ]] &&
       grep -q 'pam_faillock.so' "${PRE_DIR}/16-pam-password-policy.txt" 2>/dev/null &&
       grep -q 'pam_pwhistory.so' "${PRE_DIR}/16-pam-password-policy.txt" 2>/dev/null; then
        pre_pam="MODULES_PRESENT"
    fi
    if ! grep -q 'pam_faillock.so' /etc/pam.d/common-auth 2>/dev/null; then post_pam="NOT_HARDENED"; fi
    record_compare "PAM stack" "$pre_pam" "$post_pam" "POST_VALIDATED"

    local pre_up="NOT_CAPTURED" post_up
    if [[ -f "${PRE_DIR}/PRE-HARDENING-SUMMARY.txt" ]]; then
        pre_up="$(awk -F: '/Upgradeable packages:/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' "${PRE_DIR}/PRE-HARDENING-SUMMARY.txt" 2>/dev/null || true)"
        [[ -n "$pre_up" ]] || pre_up="NOT_CAPTURED"
    fi
    post_up="$(awk -F'\t' 'NR>1 {c++} END{print c+0}' "${OUT}/11-updates-classified.tsv" 2>/dev/null || echo NOT_CAPTURED)"
    record_compare "Upgradeable package count" "$pre_up" "$post_up" "INFORMATIONAL_ONLY"

    pass "PRE vs POST comparison generated: ${COMPARE_TSV}"
    record_status "pre_post_comparison" "PASS" "$COMPARE_TSV"
}

main() {
    echo "=============================================================================="
    echo " Mobileum MTA - 04 Post-Hardening Validation"
    echo "=============================================================================="
    echo "Host       : ${HOST_SHORT}"
    echo "Run ID     : ${RUN_TS}"
    echo "Evidence   : ${OUT}"
    echo "Mode       : READ-ONLY"
    echo "Scope      : OS/host stages 01-03; Exim excluded"
    echo

    check_os
    discover_source_evidence
    detect_role
    check_logging_audit
    check_sysctl
    check_permissions
    check_apparmor
    check_pam
    check_firewall
    check_current_admin_path
    check_updates
    check_services_and_runtime
    check_mount_evidence
    compare_pre_post

    if (( FAIL_COUNT > 0 )); then
        FINAL_RESULT="FAIL"
    elif (( WARN_COUNT > 0 )); then
        FINAL_RESULT="PASS_WITH_WARNINGS"
    else
        FINAL_RESULT="PASS"
    fi

    echo
    echo "=============================================================================="
    echo "04 execution complete."
    echo "Result     : ${FINAL_RESULT}"
    echo "PASS       : ${PASS_COUNT}"
    echo "WARN       : ${WARN_COUNT}"
    echo "FAIL       : ${FAIL_COUNT}"
    echo "Evidence   : ${OUT}"
    echo "Summary    : ${SUMMARY}"
    echo "Comparison : ${COMPARE_TSV}"
    echo "=============================================================================="

    if (( FAIL_COUNT > 0 )); then
        exit 2
    fi
    exit 0
}

main "$@"
