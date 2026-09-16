# Mobileum MTA Hardening – Log and Evidence Locations

This document lists the log, evidence, and backup locations used by the Mobileum MTA hardening scripts.

## Script and Log Location Mapping

| Stage / Script | What It Writes | Location |
|---|---|---|
| **01 – Logging/Audit** `01-mobileum-enable-logging-v3.sh` | Linux audit logs | `/var/log/audit/` |
|  | Main audit log | `/var/log/audit/audit.log` |
|  | Dedicated sudo activity log | `/var/log/sudo.log` |
|  | Sudo input/output session recordings | `/var/log/sudo-io/` |
|  | Persistent systemd journal | `/var/log/journal/` |
| **01 Validation** `Mobileum_MTA_OS_Logging_Audit_Validation_Tests-v3.sh` | Validation evidence | `/var/log/mobileum-security/validation/` |
| **02 – Pre-Hardening Assessment** `02-mobileum-pre-hardening-assessment-v3.1.sh` | Complete pre-hardening evidence set | `/var/log/mobileum-security/pre-hardening/<hostname>-<timestamp>/` |
|  | Assessment summary | `.../PRE-HARDENING-SUMMARY.txt` |
|  | Completion marker | `.../ASSESSMENT-COMPLETE` |
| **03 – CIS L1-Aligned OS Hardening** `03-mobileum-cis-l1-os-hardening-v1.4.sh` | Hardening execution evidence | `/var/log/mobileum-security/hardening/<hostname>-<timestamp>/` |
|  | Hardening summary | `.../HARDENING-SUMMARY.txt` |
|  | Service inventory | `.../service-inventory-all.txt` |
|  | Service review worksheet | `.../service-review-candidates.tsv` |
|  | Update classification | `.../updates-classified.tsv` |
|  | Account-aging review | `.../account-aging-review.tsv` |
| **03 Backups** | Pre-change configuration backups | `/var/backups/mobileum-os-hardening/<hostname>-<timestamp>/` |
| **UFW** | Firewall events through kernel/journal | `journalctl -k` / persistent journal |
| **04 – Post-Hardening Validation** | Proposed post-hardening evidence location | `/var/log/mobileum-security/post-hardening/<hostname>-<timestamp>/` |

## Current Project Directory Structure

```text
/var/log/mobileum-security/
├── validation/          # 01 validation evidence
├── pre-hardening/       # 02 pre-hardening assessment
├── hardening/           # 03 hardening execution evidence
└── post-hardening/      # 04 post-hardening validation

/var/backups/mobileum-os-hardening/
└── <hostname>-<timestamp>/   # 03 rollback/configuration backups
```

## Example MTA1 Hardening Evidence Directories

```text
/var/log/mobileum-security/hardening/mta1-20260916T130404Z
/var/log/mobileum-security/hardening/mta1-20260916T130608Z
/var/log/mobileum-security/hardening/mta1-20260916T131418Z
/var/log/mobileum-security/hardening/mta1-20260916T132924Z
```

Corresponding backup locations:

```text
/var/backups/mobileum-os-hardening/mta1-20260916T130404Z
/var/backups/mobileum-os-hardening/mta1-20260916T130608Z
/var/backups/mobileum-os-hardening/mta1-20260916T131418Z
/var/backups/mobileum-os-hardening/mta1-20260916T132924Z
```

## Useful Commands

### Display All Mobileum Security Evidence Directories

```bash
sudo find /var/log/mobileum-security -maxdepth 2 -type d | sort
```

### Display All Hardening Backup Directories

```bash
sudo find /var/backups/mobileum-os-hardening -maxdepth 1 -type d | sort
```

### View Audit Health

```bash
sudo auditctl -s
```

### View Recent Linux Audit Events

```bash
sudo ausearch -ts recent -i
```

### View Sudo Activity Log

```bash
sudo tail -100 /var/log/sudo.log
```

### List Recorded Sudo Sessions

```bash
sudo sudoreplay -l
```

### View Persistent Journal Disk Usage

```bash
sudo journalctl --disk-usage
```

### Verify Journal Integrity

```bash
sudo journalctl --verify
```

### View UFW Firewall Status

```bash
sudo ufw status verbose
sudo ufw status numbered
```

### View Recent UFW Kernel Events

```bash
sudo journalctl -k -n 100 | grep -i ufw
```

## Notes

- Each assessment or hardening execution uses a timestamped evidence directory.
- Stage `03` creates a corresponding timestamped backup before applying changes.
- Raw assessment evidence should not be committed to a public Git repository.
- Scripts and documentation can be maintained in GitHub, while operational evidence should remain in protected/private storage.
- Stage `04` will use a separate `post-hardening` evidence directory when the post-hardening validation script is finalized.
