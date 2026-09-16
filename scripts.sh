cd ~/mta-os-hardening

# 01
sudo bash 01-mobileum-enable-logging-v3.sh

# Validate 01
sudo bash Mobileum_MTA_OS_Logging_Audit_Validation_Tests-v3.sh

# 02 PRE baseline
sudo bash 02-mobileum-pre-hardening-assessment-v3.1.sh

# 03 initial assessment
sudo bash 03-mobileum-cis-l1-os-hardening-v1.4.sh --check

# Safe hardening
sudo bash 03-mobileum-cis-l1-os-hardening-v1.4.sh --apply-safe

# Security updates
sudo bash 03-mobileum-cis-l1-os-hardening-v1.4.sh --install-security-updates

# PAM
sudo bash 03-mobileum-cis-l1-os-hardening-v1.4.sh --apply-pam

# Test fresh SSH + sudo here

# UFW
sudo bash 03-mobileum-cis-l1-os-hardening-v1.4.sh --apply-firewall

# Test fresh SSH here

# Final 03 check
sudo bash 03-mobileum-cis-l1-os-hardening-v1.4.sh --check

# Current POST evidence method
sudo bash 02-mobileum-pre-hardening-assessment-v3.1.sh
