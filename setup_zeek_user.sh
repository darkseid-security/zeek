#!/bin/bash

###############################################################################
# Zeek Service Account Creation Script
# This script creates a dedicated system user for Zeek IDS
# Run this BEFORE installing Zeek to ensure proper service account exists
#
# Configuration is handled by harden_zeek_security.sh
###############################################################################

set -e  # Exit on any error
umask 077  # Set restrictive default permissions

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
ZEEK_USER="zeek"
ZEEK_GROUP="zeek"
ZEEK_HOME="/opt/zeek"
LOG_FILE="/var/log/zeek_user_setup.log"

###############################################################################
# Logging and Output Functions
###############################################################################

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG_FILE"
}

###############################################################################
# Prerequisite Checks
###############################################################################

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
    log_success "Running as root"
}

check_os() {
    if [[ -f /etc/debian_version ]]; then
        log_success "Detected Debian/Ubuntu system"
    elif [[ -f /etc/redhat-release ]]; then
        log_success "Detected RedHat/CentOS system"
    else
        log_warning "Unknown OS - proceeding with caution"
    fi
}

###############################################################################
# User and Group Management
###############################################################################

create_zeek_user() {
    log "Creating dedicated Zeek system user and group..."

    # Check if group already exists
    if getent group "$ZEEK_GROUP" > /dev/null 2>&1; then
        log_warning "Group '$ZEEK_GROUP' already exists"
    else
        # Create system group
        if groupadd --system "$ZEEK_GROUP"; then
            log_success "Created system group: $ZEEK_GROUP"
        else
            log_error "Failed to create group: $ZEEK_GROUP"
            exit 1
        fi
    fi

    # Check if user already exists
    if id "$ZEEK_USER" &> /dev/null; then
        log_warning "User '$ZEEK_USER' already exists"

        # Ensure user has correct properties
        usermod --system \
                --home "$ZEEK_HOME" \
                --shell /usr/sbin/nologin \
                --gid "$ZEEK_GROUP" \
                --comment "Zeek Network Security Monitor System User" \
                "$ZEEK_USER"
        log_success "Updated existing user: $ZEEK_USER"
    else
        # Create system user
        if useradd --system \
                   --home-dir "$ZEEK_HOME" \
                   --no-create-home \
                   --shell /usr/sbin/nologin \
                   --gid "$ZEEK_GROUP" \
                   --comment "Zeek Network Security Monitor System User" \
                   "$ZEEK_USER"; then
            log_success "Created system user: $ZEEK_USER"
        else
            log_error "Failed to create user: $ZEEK_USER"
            exit 1
        fi
    fi

    # Lock the account to prevent login
    passwd -l "$ZEEK_USER" > /dev/null 2>&1
    log_success "Locked user account to prevent login"

    # Verify user creation
    if id "$ZEEK_USER" &> /dev/null; then
        USER_ID=$(id -u "$ZEEK_USER")
        GROUP_ID=$(id -g "$ZEEK_USER")
        USER_SHELL=$(getent passwd "$ZEEK_USER" | cut -d: -f7)
        log_success "User verification - UID: $USER_ID, GID: $GROUP_ID, Shell: $USER_SHELL"
    else
        log_error "User verification failed"
        exit 1
    fi

    # Verify account is locked
    ACCOUNT_STATUS=$(passwd -S "$ZEEK_USER" 2>/dev/null | awk '{print $2}')
    if [[ "$ACCOUNT_STATUS" == "L" ]]; then
        log_success "Verified: Account is locked"
    else
        log_warning "Account status: $ACCOUNT_STATUS (expected: L for locked)"
    fi
}

###############################################################################
# Cleanup and Security Functions
###############################################################################

cleanup() {
    log "Performing cleanup..."

    # Secure log file permissions
    if [[ -f "$LOG_FILE" ]]; then
        chmod 640 "$LOG_FILE"
        chown root:adm "$LOG_FILE"
        log_success "Log file secured"
    fi
}


###############################################################################
# Summary Report
###############################################################################

print_summary() {
    cat << EOF

${GREEN}════════════════════════════════════════════════════════════${NC}
${GREEN}  Zeek Service Account Created Successfully!${NC}
${GREEN}════════════════════════════════════════════════════════════${NC}

${BLUE}Service Account Details:${NC}
  • User: $ZEEK_USER (UID: $(id -u $ZEEK_USER))
  • Group: $ZEEK_GROUP (GID: $(id -g $ZEEK_GROUP))
  • Home Directory: $ZEEK_HOME
  • Shell: /usr/sbin/nologin (login disabled)
  • Account Status: Locked (password authentication disabled)

${BLUE}Next Steps:${NC}
  1. Install Zeek IDS if not already installed
  2. Run harden_zeek_security.sh to configure Zeek with proper permissions
     and security hardening

${BLUE}Security Notes:${NC}
  • This account cannot be used for interactive login
  • Password authentication is disabled
  • Account is suitable for running system services

${BLUE}Audit Log:${NC}
  • Full log: $LOG_FILE

${GREEN}════════════════════════════════════════════════════════════${NC}

EOF
}

# Set trap to cleanup on exit
trap cleanup EXIT

###############################################################################
# Main Execution Flow
###############################################################################

main() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          Zeek Service Account Creation                ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""

    log "Starting Zeek service account creation..."

    # Phase 1: Prerequisites
    log "Phase 1: Prerequisite Checks"
    check_root
    check_os

    # Phase 2: User Management
    log "Phase 2: User and Group Creation"
    create_zeek_user

    # Phase 3: Summary
    print_summary

    log_success "Service account creation completed successfully!"
    log "Next: Install Zeek and run harden_zeek_security.sh for configuration"
}

# Run main function
main "$@"
