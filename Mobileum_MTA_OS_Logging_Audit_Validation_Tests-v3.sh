#!/usr/bin/env bash
# ==============================================================================
# Mobileum MTA - OS Logging & Audit Validation Tests v3
# Target OS : Ubuntu Server 24.04 LTS
# Purpose   : Validate the OS Logging & Audit baseline deployed by
#             01-mobileum-enable-logging-v3.sh
#
# Scope
# -----
# This script validates OS-level logging and audit only.
# Exim-specific security/hardening is intentionally excluded.
#
# The script is primarily read-only. It performs one controlled audit test:
#   /etc/systemd/system/mobileum-audit-test
# The file is created and immediately removed to verify systemd_config auditing.
#
# Usage
# -----
#   sudo bash Mobileum_MTA_OS_Logging_Audit_Validation_Tests-v3.sh
#
# Result
# ------
# A timestamped validation report is written under:
#   /var/log/mobileum-security/validation/
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="3.0"
TIMESTAMP="$(date -u +'%Y%m%dT%H%M%SZ')"
HOST_SHORT="$(hostname -s 2>/dev/null || hostname)"

REPORT_BASE="/var/log/mobileum-security/validation"
REPORT_DIR="${REPORT_BASE}/${HOST_SHORT}-${TIMESTAMP}"
REPORT_FILE="${REPORT_DIR}/validation-report.txt"

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

mkdir -p "$REPORT_DIR"
chmod 0700 "$REPORT_DIR"

exec > >(tee -a "$REPORT_FILE") 2>&1

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    printf '[PASS] %s\n' "$*"
}

warn() {
    WARN_COUNT=$((WARN_COUNT + 1))
    printf '[WARN] %s\n' "$*"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf '[FAIL] %s\n' "$*"
}

section() {
    printf '\n==============================================================================\n'
    printf '%s\n' "$*"
    printf '==============================================================================\n'
}

need_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "ERROR: Run as root, e.g.: sudo bash $SCRIPT_NAME"
        exit 1
    fi
}

cmd_exists() {
    command -v "$1" >/dev/null 2>&1
}

need_root

section "Mobileum MTA - OS Logging & Audit Validation v${SCRIPT_VERSION}"
echo "Host       : ${HOST_SHORT}"
echo "UTC time   : ${TIMESTAMP}"
echo "Report     : ${REPORT_FILE}"
echo "Scope      : OS Logging & Audit only; Exim excluded"

# ------------------------------------------------------------------------------
# T01 - Logging services
# ------------------------------------------------------------------------------

section "T01 - Logging Services Status"

for svc in systemd-journald rsyslog auditd; do
    if systemctl is-active --quiet "$svc"; then
        pass "$svc is active"
    else
        fail "$svc is NOT active"
    fi
done

systemctl --no-pager --full status systemd-journald rsyslog auditd 2>&1 || true

# ------------------------------------------------------------------------------
# T02 - Linux Audit kernel status
# ------------------------------------------------------------------------------

section "T02 - Linux Audit Kernel Status"

if ! cmd_exists auditctl; then
    fail "auditctl is not installed"
else
    auditctl -s

    AUDIT_ENABLED="$(auditctl -s | awk '$1=="enabled" {print $2; exit}')"
    AUDIT_FAILURE="$(auditctl -s | awk '$1=="failure" {print $2; exit}')"
    AUDIT_BACKLOG_LIMIT="$(auditctl -s | awk '$1=="backlog_limit" {print $2; exit}')"
    AUDIT_LOST="$(auditctl -s | awk '$1=="lost" {print $2; exit}')"
    AUDIT_BACKLOG="$(auditctl -s | awk '$1=="backlog" {print $2; exit}')"

    [[ "$AUDIT_ENABLED" == "1" ]] \
        && pass "audit enabled=1 (enabled and runtime-modifiable)" \
        || fail "Expected audit enabled=1; found ${AUDIT_ENABLED:-unknown}"

    [[ "$AUDIT_FAILURE" == "1" ]] \
        && pass "audit failure mode=1" \
        || warn "Expected failure=1; found ${AUDIT_FAILURE:-unknown}"

    [[ "$AUDIT_BACKLOG_LIMIT" == "8192" ]] \
        && pass "audit backlog_limit=8192" \
        || warn "Expected backlog_limit=8192; found ${AUDIT_BACKLOG_LIMIT:-unknown}"

    [[ "$AUDIT_LOST" == "0" ]] \
        && pass "audit lost=0" \
        || fail "Audit events have been lost: lost=${AUDIT_LOST:-unknown}"

    [[ "$AUDIT_BACKLOG" == "0" ]] \
        && pass "audit backlog=0" \
        || warn "Audit backlog is currently ${AUDIT_BACKLOG:-unknown}"
fi

# ------------------------------------------------------------------------------
# T03 - Audit rules
# ------------------------------------------------------------------------------

section "T03 - Audit Rule Loading"

RULE_OUTPUT="${REPORT_DIR}/audit-rules.txt"
auditctl -l | tee "$RULE_OUTPUT"

required_rules=(
    "/etc/passwd"
    "/etc/sudoers"
    "/etc/ssh/sshd_config"
    "/etc/netplan"
    "/etc/systemd/system"
    "/etc/pam.d"
    "/etc/apparmor.d"
    "/etc/audit"
    "/etc/apt"
    "key=privileged"
    "key=delete"
    "key=mounts"
    "key=kernel_modules"
)

for rule in "${required_rules[@]}"; do
    if grep -Fq "$rule" "$RULE_OUTPUT"; then
        pass "Audit coverage present: $rule"
    else
        fail "Audit coverage missing: $rule"
    fi
done

if grep -qi 'exim' "$RULE_OUTPUT"; then
    warn "Exim-specific audit rules were found; OS baseline is intended to exclude Exim"
else
    pass "No Exim-specific audit rules present"
fi

# ------------------------------------------------------------------------------
# T04 - sudoers syntax
# ------------------------------------------------------------------------------

section "T04 - Sudoers Syntax Validation"

if visudo -c; then
    pass "sudoers configuration parses successfully"
else
    fail "sudoers configuration has syntax errors"
fi

# ------------------------------------------------------------------------------
# T05 - Journal integrity
# ------------------------------------------------------------------------------

section "T05 - systemd Journal Integrity"

JOURNAL_VERIFY="${REPORT_DIR}/journal-verify.txt"
set +e
journalctl --verify 2>&1 | tee "$JOURNAL_VERIFY"
JOURNAL_RC=${PIPESTATUS[0]}
set -e

if [[ "$JOURNAL_RC" -eq 0 ]]; then
    pass "journalctl --verify completed successfully"
else
    fail "journalctl --verify returned exit code ${JOURNAL_RC}"
fi

if grep -q '^PASS:' "$JOURNAL_VERIFY"; then
    pass "Journal files report PASS"
else
    warn "No PASS lines detected in journal verification output"
fi

if grep -q 'Unused data (entry_offset==0)' "$JOURNAL_VERIFY"; then
    warn "Journal contains informational 'Unused data' records; files still pass verification"
fi

# ------------------------------------------------------------------------------
# T06 - sudo privilege execution
# ------------------------------------------------------------------------------

section "T06 - Sudo Privilege Execution"

# The script itself is already running as root. Use sudo -u root only if sudo is
# available so that sudo policy/logging is exercised.
if cmd_exists sudo; then
    if sudo whoami | grep -qx root; then
        pass "sudo whoami returns root"
    else
        fail "sudo whoami did not return root"
    fi

    if sudo ls /root >/dev/null 2>&1; then
        pass "sudo access to /root succeeded"
    else
        fail "sudo access to /root failed"
    fi
else
    fail "sudo command not installed"
fi

# ------------------------------------------------------------------------------
# T07 - Detailed sudo logging
# ------------------------------------------------------------------------------

section "T07 - Detailed Sudo Command Logging"

if [[ -f /var/log/sudo.log ]]; then
    tail -30 /var/log/sudo.log
    if grep -q 'COMMAND=' /var/log/sudo.log; then
        pass "/var/log/sudo.log contains sudo command records"
    else
        fail "/var/log/sudo.log exists but no COMMAND= records were found"
    fi
else
    fail "/var/log/sudo.log does not exist"
fi

# ------------------------------------------------------------------------------
# T08 - sudo I/O session recording
# ------------------------------------------------------------------------------

section "T08 - Sudo I/O Session Recording"

if cmd_exists sudoreplay; then
    SUDOREPLAY_OUT="${REPORT_DIR}/sudoreplay-list.txt"
    sudoreplay -l 2>&1 | tee "$SUDOREPLAY_OUT" || true

    if grep -q 'TSID=' "$SUDOREPLAY_OUT"; then
        pass "sudoreplay reports recorded sudo I/O sessions"
    else
        warn "No TSID entries found in sudoreplay output"
    fi
else
    fail "sudoreplay command not found"
fi

# ------------------------------------------------------------------------------
# T09 - OS configuration-change auditing
# ------------------------------------------------------------------------------

section "T09 - OS Configuration-Change Auditing"

TEST_FILE="/etc/systemd/system/mobileum-audit-test"

rm -f "$TEST_FILE"
touch "$TEST_FILE"
rm -f "$TEST_FILE"

sleep 1

SYSTEMD_AUDIT="${REPORT_DIR}/systemd-config-audit.txt"
ausearch -k systemd_config -ts recent -i 2>&1 | tee "$SYSTEMD_AUDIT" || true

if grep -q 'mobileum-audit-test' "$SYSTEMD_AUDIT" && \
   grep -q 'nametype=CREATE' "$SYSTEMD_AUDIT" && \
   grep -q 'nametype=DELETE' "$SYSTEMD_AUDIT"; then
    pass "Create/delete activity under /etc/systemd/system was audited"
else
    fail "Expected create/delete audit records were not found"
fi

if grep -Eq 'auid=[^ ]+' "$SYSTEMD_AUDIT"; then
    pass "Audit records contain AUID attribution"
else
    warn "Could not confirm AUID attribution in systemd_config output"
fi

# ------------------------------------------------------------------------------
# T10 - Privileged command visibility ("test1")
# ------------------------------------------------------------------------------

section "T10 - Privileged Command Audit Visibility (test1)"

TEST1_OUT="${REPORT_DIR}/test1-privileged-commands.txt"

ausearch -k privileged -ts recent -i 2>/dev/null |
grep 'type=PROCTITLE' |
sed -n 's/.*proctitle=//p' |
grep '^sudo ' |
tail -30 | tee "$TEST1_OUT" || true

if [[ -s "$TEST1_OUT" ]]; then
    pass "test1 returned recent explicit sudo commands"
else
    warn "test1 returned no explicit sudo commands in the recent audit window"
fi

echo
echo "Standard test1 command:"
cat <<'EOF'
sudo ausearch -k privileged -ts recent -i |
grep 'type=PROCTITLE' |
sed -n 's/.*proctitle=//p' |
grep '^sudo ' |
tail -30
EOF

# ------------------------------------------------------------------------------
# T11 - Bash history configuration
# ------------------------------------------------------------------------------

section "T11 - Bash History Configuration"

PROFILE_FILE="/etc/profile.d/mta-history.sh"

if [[ -f "$PROFILE_FILE" ]]; then
    pass "$PROFILE_FILE exists"
    cat "$PROFILE_FILE"
else
    fail "$PROFILE_FILE does not exist"
fi

# Verify intended policy in both system baseline and existing Bash users.
if grep -q 'HISTSIZE=100000' "$PROFILE_FILE" 2>/dev/null; then
    pass "System Bash history policy contains HISTSIZE=100000"
else
    fail "System Bash history policy does not contain HISTSIZE=100000"
fi

if grep -q 'HISTFILESIZE=200000' "$PROFILE_FILE" 2>/dev/null; then
    pass "System Bash history policy contains HISTFILESIZE=200000"
else
    fail "System Bash history policy does not contain HISTFILESIZE=200000"
fi

HISTORY_OVERRIDE_FILE="${REPORT_DIR}/bash-history-assignments.txt"
grep -RnsE '^[[:space:]]*(HISTSIZE|HISTFILESIZE)=' \
    /root/.bashrc /etc/skel/.bashrc /home/*/.bashrc 2>/dev/null |
    tee "$HISTORY_OVERRIDE_FILE" || true

BAD_HISTORY=0
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if [[ "$line" == *"HISTSIZE="* && "$line" != *"HISTSIZE=100000"* ]]; then
        BAD_HISTORY=1
    fi
    if [[ "$line" == *"HISTFILESIZE="* && "$line" != *"HISTFILESIZE=200000"* ]]; then
        BAD_HISTORY=1
    fi
done < "$HISTORY_OVERRIDE_FILE"

if [[ "$BAD_HISTORY" -eq 0 ]]; then
    pass "Existing Bash profile history-size assignments match Mobileum baseline"
else
    fail "One or more Bash profiles override the Mobileum history-size baseline"
fi

echo
echo "NOTE: Effective shell values must be checked from a NEW SSH session:"
cat <<'EOF'
echo "$HISTSIZE"
echo "$HISTFILESIZE"
echo "$HISTTIMEFORMAT"
shopt histappend
echo "$PROMPT_COMMAND"
EOF

# ------------------------------------------------------------------------------
# T12 - Bash history timestamps
# ------------------------------------------------------------------------------

section "T12 - Bash History Timestamp Policy"

if grep -Fq "HISTTIMEFORMAT='%F %T '" "$PROFILE_FILE" 2>/dev/null; then
    pass "Bash history timestamp policy is configured"
else
    fail "Bash history timestamp policy is missing"
fi

if grep -Fq 'shopt -s histappend' "$PROFILE_FILE" 2>/dev/null; then
    pass "histappend is configured"
else
    fail "histappend configuration is missing"
fi

if grep -Fq 'history -a; history -n' "$PROFILE_FILE" 2>/dev/null; then
    pass "Cross-session immediate history append/import is configured"
else
    fail "PROMPT_COMMAND history append/import is missing"
fi

# ------------------------------------------------------------------------------
# T13 - Audit lost events
# ------------------------------------------------------------------------------

section "T13 - Audit Health / Lost Event Check"

AUDIT_STATUS_FINAL="$(auditctl -s)"
echo "$AUDIT_STATUS_FINAL"

FINAL_LOST="$(awk '$1=="lost" {print $2; exit}' <<<"$AUDIT_STATUS_FINAL")"
FINAL_BACKLOG="$(awk '$1=="backlog" {print $2; exit}' <<<"$AUDIT_STATUS_FINAL")"

[[ "$FINAL_LOST" == "0" ]] \
    && pass "No audit events lost" \
    || fail "Audit lost counter is ${FINAL_LOST:-unknown}"

[[ "$FINAL_BACKLOG" == "0" ]] \
    && pass "No current audit backlog" \
    || warn "Audit backlog is ${FINAL_BACKLOG:-unknown}"

# ------------------------------------------------------------------------------
# T14 - Log-storage growth
# ------------------------------------------------------------------------------

section "T14 - Log Storage Growth"

du -sh /var/log/audit 2>/dev/null || true
du -sh /var/log/sudo-io 2>/dev/null || true
journalctl --disk-usage || true

pass "Log storage measurements captured for customer evidence"

# ------------------------------------------------------------------------------
# T15 - Runtime audit modification policy
# ------------------------------------------------------------------------------

section "T15 - Audit Runtime Modification Policy"

FINAL_ENABLED="$(auditctl -s | awk '$1=="enabled" {print $2; exit}')"

if [[ "$FINAL_ENABLED" == "1" ]]; then
    pass "Audit enabled=1; runtime rule changes remain possible without reboot"
elif [[ "$FINAL_ENABLED" == "2" ]]; then
    fail "Audit enabled=2 (immutable); this conflicts with the Mobileum no-reboot policy"
else
    fail "Unexpected audit enabled state: ${FINAL_ENABLED:-unknown}"
fi

# ------------------------------------------------------------------------------
# Final summary
# ------------------------------------------------------------------------------

section "FINAL VALIDATION SUMMARY"

echo "PASS : ${PASS_COUNT}"
echo "WARN : ${WARN_COUNT}"
echo "FAIL : ${FAIL_COUNT}"
echo
echo "Detailed report:"
echo "  ${REPORT_FILE}"
echo
echo "Supporting evidence directory:"
echo "  ${REPORT_DIR}"
echo

if [[ "$FAIL_COUNT" -eq 0 ]]; then
    echo "OVERALL RESULT: PASS"
    echo
    echo "The Mobileum OS Logging & Audit baseline is operationally validated."
    exit 0
else
    echo "OVERALL RESULT: FAIL"
    echo
    echo "Review the failed tests before deploying to the production MTA."
    exit 1
fi
