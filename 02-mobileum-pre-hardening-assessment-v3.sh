#!/usr/bin/env bash
# ==============================================================================
# Mobileum MTA - 02 Pre-Hardening Assessment v2
# Target OS : Ubuntu Server 24.04 LTS
# Scope     : OS / host security baseline only
#
# Purpose
# -------
# Capture the complete PRE-HARDENING evidence set before CIS Level 1
# remediation is applied.
#
# This script is intentionally READ-ONLY:
#   - It does NOT install packages
#   - It does NOT change sysctl values
#   - It does NOT modify SSH, firewall, users, services, mounts or packages
#   - It does NOT configure Exim
#
# Exim/application hardening and SMTP-specific testing are handled separately.
#
# Usage
# -----
#   sudo bash 02-mobileum-pre-hardening-assessment-v2.sh
#
# Output
# ------
#   /var/log/mobileum-security/pre-hardening/<host>-<timestamp>/
#
# Notes
# -----
# Some commands may not exist on every Ubuntu image. Missing optional tools are
# recorded as "NOT AVAILABLE" rather than causing the assessment to fail.
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'
umask 027

SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="2.0"
TIMESTAMP="$(date -u +'%Y%m%dT%H%M%SZ')"
HOST_SHORT="$(hostname -s 2>/dev/null || hostname)"

BASE="/var/log/mobileum-security/pre-hardening"
OUT="${BASE}/${HOST_SHORT}-${TIMESTAMP}"
SUMMARY="${OUT}/PRE-HARDENING-SUMMARY.txt"

mkdir -p "$OUT"
chmod 0700 "$OUT"

PASS=0
WARN=0
INFO=0

log()  { printf '%s [INFO] %s\n' "$(date +'%F %T')" "$*"; }
pass() { PASS=$((PASS+1)); printf '[PASS] %s\n' "$*"; }
warn() { WARN=$((WARN+1)); printf '[WARN] %s\n' "$*"; }
info() { INFO=$((INFO+1)); printf '[INFO] %s\n' "$*"; }

need_root() {
    [[ "$EUID" -eq 0 ]] || {
        echo "ERROR: Run as root: sudo bash ${SCRIPT_NAME}"
        exit 1
    }
}

have() { command -v "$1" >/dev/null 2>&1; }

capture() {
    local file="$1"; shift

    # IMPORTANT:
    # Run the capture body in a SUBSHELL. Earlier versions used a brace group
    # containing "exit 0", which exited the entire assessment script after the
    # first evidence file. The subshell isolates the command exit status and
    # allows the assessment to continue through all sections.
    (
        set +e
        printf '# Command:'
        printf ' %q' "$@"
        printf '\n# Captured: %s\n\n' "$(date --iso-8601=seconds)"
        "$@"
        rc=$?
        printf '\n# Exit status: %s\n' "$rc"
        exit 0
    ) >"${OUT}/${file}" 2>&1
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
    ) >"${OUT}/${file}" 2>&1
}

need_root

exec > >(tee -a "${OUT}/00-assessment-run.log") 2>&1

echo "=============================================================================="
echo " Mobileum MTA - 02 Pre-Hardening Assessment v${SCRIPT_VERSION}"
echo "=============================================================================="
echo "Host      : ${HOST_SHORT}"
echo "UTC       : ${TIMESTAMP}"
echo "Output    : ${OUT}"
echo "Mode      : READ-ONLY"
echo "Scope     : OS/host baseline only; Exim excluded"
echo

# ------------------------------------------------------------------------------
# 01 - System identity / OS / kernel
# ------------------------------------------------------------------------------

log "Collecting system identity and OS information."

capture_shell "01-system-info.txt" '
echo "### /etc/os-release"
cat /etc/os-release
echo
echo "### hostnamectl"
hostnamectl
echo
echo "### uname"
uname -a
echo
echo "### architecture"
dpkg --print-architecture 2>/dev/null || true
echo
echo "### uptime"
uptime
echo
echo "### date/time"
date --iso-8601=seconds
timedatectl 2>/dev/null || true
echo
echo "### cloud metadata availability (no token/request made)"
systemctl status cloud-init --no-pager 2>/dev/null || true
'

# ------------------------------------------------------------------------------
# 02 - CPU, memory, block devices, filesystems
# ------------------------------------------------------------------------------

log "Collecting hardware/storage/filesystem baseline."

capture_shell "02-hardware-storage.txt" '
echo "### CPU"
lscpu
echo
echo "### Memory"
free -h
echo
echo "### Block devices"
lsblk -o NAME,KNAME,TYPE,SIZE,FSTYPE,FSVER,MOUNTPOINTS,UUID,ROTA,MODEL
echo
echo "### Filesystems"
df -hT
echo
echo "### Inodes"
df -hi
echo
echo "### Mounts"
findmnt -A -o TARGET,SOURCE,FSTYPE,OPTIONS
echo
echo "### /etc/fstab"
cat /etc/fstab
'

# ------------------------------------------------------------------------------
# 03 - Installed packages / repositories
# ------------------------------------------------------------------------------

log "Collecting package and repository baseline."

capture_shell "03-packages-installed.txt" '
dpkg-query -W -f="${binary:Package}\t${Version}\n" | sort
'

capture_shell "03-apt-sources.txt" '
echo "### /etc/apt/sources.list"
cat /etc/apt/sources.list 2>/dev/null || true
echo
echo "### /etc/apt/sources.list.d"
for f in /etc/apt/sources.list.d/*; do
    [ -f "$f" ] || continue
    echo "----- $f -----"
    cat "$f"
done
'

# ------------------------------------------------------------------------------
# 04 - Pending updates / package-security indicators
# ------------------------------------------------------------------------------

log "Collecting pending update/security indicators."

capture_shell "04-updates-security.txt" '
echo "### apt list --upgradable"
apt list --upgradable 2>/dev/null || true
echo
echo "### Simulated normal upgrade"
apt-get -s upgrade 2>/dev/null || true
echo
echo "### Simulated dist-upgrade"
apt-get -s dist-upgrade 2>/dev/null || true
echo
echo "### unattended-upgrades configuration"
dpkg -l unattended-upgrades 2>/dev/null || true
systemctl status unattended-upgrades --no-pager 2>/dev/null || true
echo
echo "### ubuntu-security-status (if available)"
if command -v ubuntu-security-status >/dev/null 2>&1; then
    ubuntu-security-status
else
    echo "NOT AVAILABLE"
fi
echo
echo "### pro security-status (if command exists; no subscription required for query)"
if command -v pro >/dev/null 2>&1; then
    pro security-status 2>&1 || true
else
    echo "NOT AVAILABLE"
fi
'

# ------------------------------------------------------------------------------
# 05 - Running services / enabled services / failed units
# ------------------------------------------------------------------------------

log "Collecting service baseline."

capture_shell "05-services.txt" '
echo "### Running services"
systemctl list-units --type=service --state=running --no-pager --no-legend
echo
echo "### Enabled services"
systemctl list-unit-files --type=service --state=enabled --no-pager
echo
echo "### Failed units"
systemctl --failed --no-pager
echo
echo "### Timers"
systemctl list-timers --all --no-pager
'

# ------------------------------------------------------------------------------
# 06 - Listening ports and network sockets
# ------------------------------------------------------------------------------

log "Collecting listening-port and socket baseline."

capture_shell "06-listening-ports.txt" '
echo "### TCP/UDP listeners"
ss -lntup
echo
echo "### TCP listeners with process info"
ss -lntp
echo
echo "### UDP listeners with process info"
ss -lnup
'

# ------------------------------------------------------------------------------
# 07 - Network configuration / routing / DNS / interfaces
# ------------------------------------------------------------------------------

log "Collecting network baseline."

capture_shell "07-network.txt" '
echo "### Interfaces"
ip -br addr
echo
echo "### Links"
ip -br link
echo
echo "### Routes"
ip route
echo
ip -6 route 2>/dev/null || true
echo
echo "### Rules"
ip rule
echo
echo "### Netplan"
netplan get 2>/dev/null || true
echo
echo "### resolvectl"
resolvectl status 2>/dev/null || true
echo
echo "### /etc/resolv.conf"
ls -l /etc/resolv.conf
cat /etc/resolv.conf
'

# ------------------------------------------------------------------------------
# 08 - Users, groups, login shells, UID 0, empty-password checks
# ------------------------------------------------------------------------------

log "Collecting account and identity baseline."

capture_shell "08-users-groups.txt" '
echo "### passwd database"
getent passwd
echo
echo "### group database"
getent group
echo
echo "### UID 0 accounts"
awk -F: "$3 == 0 {print}" /etc/passwd
echo
echo "### Interactive shell users"
awk -F: '\''$7 ~ /(bash|sh|zsh|ksh)$/ {print $1 ":" $3 ":" $6 ":" $7}'\'' /etc/passwd
echo
echo "### Shadow status"
passwd -Sa 2>/dev/null || true
echo
echo "### Empty password fields"
awk -F: '\''($2 == "") {print $1}'\'' /etc/shadow
echo
echo "### Recent logins"
last -n 50
echo
echo "### Failed logins"
lastb -n 50 2>/dev/null || true
'

# ------------------------------------------------------------------------------
# 09 - sudo configuration
# ------------------------------------------------------------------------------

log "Collecting sudo baseline."

capture_shell "09-sudo.txt" '
echo "### visudo validation"
visudo -c
echo
echo "### /etc/sudoers"
sed -n "1,240p" /etc/sudoers
echo
echo "### /etc/sudoers.d"
for f in /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    echo "----- $f -----"
    cat "$f"
done
echo
echo "### sudo log evidence"
tail -100 /var/log/sudo.log 2>/dev/null || true
'

# ------------------------------------------------------------------------------
# 10 - SSH effective configuration
# ------------------------------------------------------------------------------

log "Collecting SSH server baseline."

capture_shell "10-ssh.txt" '
echo "### sshd effective configuration"
if command -v sshd >/dev/null 2>&1; then
    sshd -T
else
    echo "sshd NOT INSTALLED"
fi
echo
echo "### Main sshd_config"
cat /etc/ssh/sshd_config 2>/dev/null || true
echo
echo "### sshd_config.d"
for f in /etc/ssh/sshd_config.d/*; do
    [ -f "$f" ] || continue
    echo "----- $f -----"
    cat "$f"
done
'

# ------------------------------------------------------------------------------
# 11 - Firewall / nftables / UFW
# ------------------------------------------------------------------------------

log "Collecting host-firewall baseline."

capture_shell "11-firewall.txt" '
echo "### UFW"
ufw status verbose 2>&1 || true
echo
echo "### nftables"
if command -v nft >/dev/null 2>&1; then
    nft list ruleset
else
    echo "nft command NOT AVAILABLE"
fi
echo
echo "### iptables compatibility view"
iptables -S 2>/dev/null || true
ip6tables -S 2>/dev/null || true
'

# ------------------------------------------------------------------------------
# 12 - AppArmor
# ------------------------------------------------------------------------------

log "Collecting AppArmor baseline."

capture_shell "12-apparmor.txt" '
echo "### AppArmor service"
systemctl status apparmor --no-pager 2>/dev/null || true
echo
echo "### AppArmor status"
if command -v aa-status >/dev/null 2>&1; then
    aa-status
else
    echo "aa-status NOT AVAILABLE"
fi
'

# ------------------------------------------------------------------------------
# 13 - Audit/logging
# ------------------------------------------------------------------------------

log "Collecting audit/logging baseline."

capture_shell "13-audit-logging.txt" '
echo "### auditctl -s"
auditctl -s 2>/dev/null || true
echo
echo "### auditctl -l"
auditctl -l 2>/dev/null || true
echo
echo "### journald effective config"
systemd-analyze cat-config systemd/journald.conf 2>/dev/null || true
echo
echo "### journal disk usage"
journalctl --disk-usage 2>/dev/null || true
echo
echo "### rsyslog syntax"
rsyslogd -N1 2>&1 || true
echo
echo "### sudo logging"
ls -ld /var/log/sudo.log /var/log/sudo-io 2>/dev/null || true
echo
echo "### Mobileum logging baseline files"
stat /etc/profile.d/mta-history.sh \
     /etc/systemd/journald.conf.d/10-mta-logging.conf \
     /etc/sudoers.d/mta-audit \
     /etc/audit/rules.d/99-mobileum-logging.rules 2>/dev/null || true
'

# ------------------------------------------------------------------------------
# 14 - sysctl / kernel security / network parameters
# ------------------------------------------------------------------------------

log "Collecting kernel/sysctl security baseline."

capture_shell "14-sysctl-security.txt" '
keys="
kernel.randomize_va_space
kernel.kptr_restrict
kernel.dmesg_restrict
kernel.yama.ptrace_scope
kernel.unprivileged_bpf_disabled
fs.suid_dumpable
fs.protected_fifos
fs.protected_hardlinks
fs.protected_regular
fs.protected_symlinks
net.ipv4.ip_forward
net.ipv4.conf.all.forwarding
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
net.ipv4.conf.all.rp_filter
net.ipv4.conf.default.rp_filter
net.ipv4.tcp_syncookies
net.ipv6.conf.all.accept_redirects
net.ipv6.conf.default.accept_redirects
net.ipv6.conf.all.accept_source_route
net.ipv6.conf.default.accept_source_route
"
for k in $keys; do
    printf "%-48s = " "$k"
    sysctl -n "$k" 2>/dev/null || echo "NOT AVAILABLE"
done
echo
echo "### sysctl configuration files"
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
    [ -f "$f" ] || continue
    echo "----- $f -----"
    cat "$f"
done
'

# ------------------------------------------------------------------------------
# 15 - Kernel modules and module-policy configuration
# ------------------------------------------------------------------------------

log "Collecting kernel-module baseline."

capture_shell "15-kernel-modules.txt" '
echo "### Loaded modules"
lsmod
echo
echo "### modprobe configuration"
for f in /etc/modprobe.d/*.conf; do
    [ -f "$f" ] || continue
    echo "----- $f -----"
    cat "$f"
done
'

# ------------------------------------------------------------------------------
# 16 - PAM / password / account policy
# ------------------------------------------------------------------------------

log "Collecting PAM/password-policy baseline."

capture_shell "16-pam-password-policy.txt" '
echo "### login.defs relevant settings"
grep -E "^[[:space:]]*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|UMASK|ENCRYPT_METHOD|USERGROUPS_ENAB)" \
    /etc/login.defs 2>/dev/null || true
echo
echo "### pwquality"
cat /etc/security/pwquality.conf 2>/dev/null || true
for f in /etc/security/pwquality.conf.d/*.conf; do
    [ -f "$f" ] || continue
    echo "----- $f -----"
    cat "$f"
done
echo
echo "### PAM common-auth"
cat /etc/pam.d/common-auth 2>/dev/null || true
echo
echo "### PAM common-account"
cat /etc/pam.d/common-account 2>/dev/null || true
echo
echo "### PAM common-password"
cat /etc/pam.d/common-password 2>/dev/null || true
echo
echo "### faillock"
grep -R "pam_faillock" /etc/pam.d /etc/security 2>/dev/null || true
'

# ------------------------------------------------------------------------------
# 17 - File permission checks for critical OS files
# ------------------------------------------------------------------------------

log "Collecting critical-file permission baseline."

capture_shell "17-critical-file-permissions.txt" '
for f in \
  /etc/passwd \
  /etc/group \
  /etc/shadow \
  /etc/gshadow \
  /etc/sudoers \
  /etc/ssh/sshd_config \
  /etc/crontab \
  /etc/audit/auditd.conf
do
    [ -e "$f" ] && stat -c "%A %a %U:%G %n" "$f"
done
echo
echo "### sudoers.d"
find /etc/sudoers.d -maxdepth 1 -type f -exec stat -c "%A %a %U:%G %n" {} \; 2>/dev/null | sort
echo
echo "### SSH config drop-ins"
find /etc/ssh/sshd_config.d -maxdepth 1 -type f -exec stat -c "%A %a %U:%G %n" {} \; 2>/dev/null | sort
'

# ------------------------------------------------------------------------------
# 18 - Cron/at
# ------------------------------------------------------------------------------

log "Collecting scheduled-task baseline."

capture_shell "18-cron-at.txt" '
echo "### cron service"
systemctl status cron --no-pager 2>/dev/null || true
echo
echo "### /etc/crontab"
cat /etc/crontab 2>/dev/null || true
echo
echo "### cron directories"
for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    echo "----- $d -----"
    ls -la "$d" 2>/dev/null || true
done
echo
echo "### at"
systemctl status atd --no-pager 2>/dev/null || true
ls -l /etc/at.allow /etc/at.deny 2>/dev/null || true
'

# ------------------------------------------------------------------------------
# 19 - Time synchronization
# ------------------------------------------------------------------------------

log "Collecting time-sync baseline."

capture_shell "19-time-sync.txt" '
timedatectl
echo
timedatectl timesync-status 2>/dev/null || true
echo
systemctl status systemd-timesyncd --no-pager 2>/dev/null || true
systemctl status chrony --no-pager 2>/dev/null || true
'

# ------------------------------------------------------------------------------
# 20 - Boot / GRUB / secure boot
# ------------------------------------------------------------------------------

log "Collecting boot-security baseline."

capture_shell "20-boot-security.txt" '
echo "### Kernel command line"
cat /proc/cmdline
echo
echo "### GRUB permissions"
stat -c "%A %a %U:%G %n" /boot/grub/grub.cfg 2>/dev/null || true
echo
echo "### Secure Boot"
if command -v mokutil >/dev/null 2>&1; then
    mokutil --sb-state 2>&1 || true
else
    echo "mokutil NOT AVAILABLE"
fi
'

# ------------------------------------------------------------------------------
# 21 - World-writable / SUID / SGID inventory
# ------------------------------------------------------------------------------

log "Collecting filesystem privilege inventory. This may take a little longer."

capture_shell "21-suid-sgid-world-writable.txt" '
echo "### SUID files (local filesystems only)"
find / -xdev -type f -perm -4000 -print 2>/dev/null | sort
echo
echo "### SGID files (local filesystems only)"
find / -xdev -type f -perm -2000 -print 2>/dev/null | sort
echo
echo "### World-writable files (local filesystems only)"
find / -xdev -type f -perm -0002 -print 2>/dev/null | sort
echo
echo "### World-writable directories without sticky bit"
find / -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | sort
'

# ------------------------------------------------------------------------------
# 22 - Optional security-assessment tools already installed
# ------------------------------------------------------------------------------

log "Checking optional local security assessment tools (no installation)."

capture_shell "22-optional-security-tools.txt" '
for c in lynis oscap debsecan clamav freshclam; do
    if command -v "$c" >/dev/null 2>&1; then
        echo "$c: AVAILABLE at $(command -v "$c")"
        "$c" --version 2>&1 | head -5 || true
    else
        echo "$c: NOT AVAILABLE"
    fi
done
'

if have lynis; then
    log "Lynis is already installed; running read-only system audit."
    lynis audit system --quick --no-colors >"${OUT}/22-lynis-audit.txt" 2>&1 || true
fi

# ------------------------------------------------------------------------------
# 23 - Simple findings summary (not a CIS certification result)
# ------------------------------------------------------------------------------

log "Generating preliminary findings summary."

{
    echo "=============================================================================="
    echo " MOBILEUM MTA - PRE-HARDENING SUMMARY"
    echo "=============================================================================="
    echo
    echo "Host      : ${HOST_SHORT}"
    echo "UTC       : ${TIMESTAMP}"
    echo "Script    : ${SCRIPT_NAME} v${SCRIPT_VERSION}"
    echo "Mode      : READ-ONLY"
    echo
    echo "IMPORTANT:"
    echo "This is an evidence/baseline assessment, NOT a formal CIS certification."
    echo "Exim is intentionally excluded."
    echo

    echo "---- OS ----"
    . /etc/os-release
    echo "OS              : ${PRETTY_NAME:-unknown}"
    echo "Kernel          : $(uname -r)"
    echo "Architecture    : $(uname -m)"
    echo

    echo "---- Listening TCP ports ----"
    ss -lntp 2>/dev/null || true
    echo

    echo "---- Failed systemd units ----"
    systemctl --failed --no-legend --no-pager 2>/dev/null || true
    echo

    echo "---- Audit health ----"
    auditctl -s 2>/dev/null || true
    echo

    echo "---- Firewall ----"
    ufw status verbose 2>/dev/null || true
    echo

    echo "---- AppArmor ----"
    aa-status 2>/dev/null || true
    echo

    echo "---- SSH selected effective settings ----"
    if command -v sshd >/dev/null 2>&1; then
        sshd -T 2>/dev/null | grep -E \
          '^(permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|maxauthtries|maxsessions|maxstartups|x11forwarding|allowtcpforwarding|clientaliveinterval|clientalivecountmax|loglevel|usepam) ' \
          || true
    fi
    echo

    echo "---- Pending upgrade count ----"
    UPGRADES="$(apt list --upgradable 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')"
    echo "Upgradeable packages: ${UPGRADES}"
    echo

    echo "---- UID 0 accounts ----"
    awk -F: '$3 == 0 {print $1}' /etc/passwd
    echo

    echo "---- Empty-password accounts ----"
    EMPTY="$(awk -F: '($2 == "") {print $1}' /etc/shadow | xargs)"
    if [[ -n "$EMPTY" ]]; then
        echo "$EMPTY"
    else
        echo "None"
    fi
    echo

    echo "---- Preliminary observations ----"

    # Audit
    AUDIT_ENABLED="$(auditctl -s 2>/dev/null | awk '$1=="enabled"{print $2;exit}')"
    AUDIT_LOST="$(auditctl -s 2>/dev/null | awk '$1=="lost"{print $2;exit}')"
    if [[ "$AUDIT_ENABLED" == "1" && "$AUDIT_LOST" == "0" ]]; then
        echo "[PASS] Audit enabled and lost=0"
    else
        echo "[WARN] Audit state requires review: enabled=${AUDIT_ENABLED:-unknown}, lost=${AUDIT_LOST:-unknown}"
    fi

    # Firewall
    if ufw status 2>/dev/null | grep -q '^Status: active'; then
        echo "[PASS] UFW is active"
    else
        echo "[WARN] UFW is not active or unavailable"
    fi

    # AppArmor
    if systemctl is-active --quiet apparmor 2>/dev/null; then
        echo "[PASS] AppArmor service is active"
    else
        echo "[WARN] AppArmor service is not active"
    fi

    # SSH root
    if command -v sshd >/dev/null 2>&1; then
        ROOT_LOGIN="$(sshd -T 2>/dev/null | awk '$1=="permitrootlogin"{print $2;exit}')"
        PASS_AUTH="$(sshd -T 2>/dev/null | awk '$1=="passwordauthentication"{print $2;exit}')"
        echo "[INFO] SSH PermitRootLogin=${ROOT_LOGIN:-unknown}"
        echo "[INFO] SSH PasswordAuthentication=${PASS_AUTH:-unknown}"
    fi

    # Updates
    if [[ "${UPGRADES:-0}" -gt 0 ]]; then
        echo "[WARN] ${UPGRADES} package(s) are currently upgradeable"
    else
        echo "[PASS] No upgradeable packages detected by current apt metadata"
    fi

    echo
    echo "---- Next steps ----"
    echo "1. Preserve this directory as PRE-hardening evidence."
    echo "2. Run the external attack-surface scan from a separate host."
    echo "3. Review the evidence against the Ubuntu 24.04 CIS Level 1 Server baseline."
    echo "4. Apply 03 - CIS Level 1 OS Hardening only after the PRE baseline is frozen."
    echo "5. Re-run equivalent tests during 04 - Post-Hardening Assessment."
    echo
    echo "Evidence directory:"
    echo "  ${OUT}"
    echo "=============================================================================="
} | tee "$SUMMARY"

touch "${OUT}/ASSESSMENT-COMPLETE"
chmod 0600 "${OUT}/ASSESSMENT-COMPLETE"

log "Pre-hardening assessment complete."
echo
echo "Summary:"
echo "  ${SUMMARY}"
echo
echo "Evidence:"
echo "  ${OUT}"
echo
echo "No remediation changes were made by this script."
