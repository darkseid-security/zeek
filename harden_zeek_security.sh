#!/bin/bash

###############################################################################
# Zeek Installation and Security Hardening Script
# This script installs Zeek IDS and configures it with proper security hardening
#
# IMPORTANT: This script is configured for Ubuntu 24.04 LTS only
# Prerequisites: Run setup_zeek_user.sh first to create the zeek service account
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
LOG_FILE="/var/log/zeek_security_hardening.log"

###############################################################################
# Logging Functions
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

check_zeek_user_exists() {
    if ! id "$ZEEK_USER" &> /dev/null; then
        log_error "Zeek user '$ZEEK_USER' does not exist"
        log_error "Please run setup_zeek_user.sh first"
        exit 1
    fi
    log_success "Zeek user exists"
}

###############################################################################
# Zeek Installation
###############################################################################

install_zeek() {
    log "Installing Zeek IDS from OpenSUSE repository..."
    log_warning "This script is configured for Ubuntu 24.04 LTS only"

    # Check if Zeek is already installed
    if [[ -f "$ZEEK_HOME/bin/zeek" ]]; then
        log_warning "Zeek is already installed at $ZEEK_HOME"
        ZEEK_VERSION=$("$ZEEK_HOME/bin/zeek" -v 2>&1 | head -n1)
        log "Installed version: $ZEEK_VERSION"
        log "Skipping installation, proceeding with configuration..."
        return 0
    fi

    # Repository URL - Ubuntu 24.04 LTS only
    ZEEK_REPO="xUbuntu_24.04"
    REPO_URL="http://download.opensuse.org/repositories/security:/zeek/${ZEEK_REPO}/"

    log "Updating package lists..."
    if ! apt-get update > /dev/null 2>&1; then
        log_error "Failed to update package lists"
        exit 1
    fi
    log_success "Package lists updated"

    log "Adding Zeek repository..."
    echo "deb ${REPO_URL} /" | tee /etc/apt/sources.list.d/security:zeek.list > /dev/null
    chmod 644 /etc/apt/sources.list.d/security:zeek.list
    log_success "Zeek repository added"

    log "Adding repository GPG key..."
    if ! curl -fsSL "https://download.opensuse.org/repositories/security:zeek/${ZEEK_REPO}/Release.key" | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null 2>&1; then
        log_error "Failed to add GPG key"
        log_error "Make sure curl is installed: apt-get install curl"
        exit 1
    fi
    chmod 644 /etc/apt/trusted.gpg.d/security_zeek.gpg
    log_success "GPG key added successfully"

    log "Updating package lists after adding repository..."
    if ! apt-get update > /dev/null 2>&1; then
        log_error "Failed to update package lists"
        exit 1
    fi
    log_success "Package lists updated"

    log "Installing Zeek (this may take 5-15 minutes)..."
    echo -e "  ${YELLOW}Downloading and installing packages...${NC}"

    # Install with non-interactive mode to prevent prompts
    INSTALL_OUTPUT=$(DEBIAN_FRONTEND=noninteractive apt-get install -y zeek 2>&1)
    INSTALL_EXIT=$?

    # Check for errors (exit code != 0 or contains error messages)
    if [[ $INSTALL_EXIT -ne 0 ]] || echo "$INSTALL_OUTPUT" | grep -q "^E:"; then
        log_error "Failed to install Zeek"
        echo "$INSTALL_OUTPUT" | grep "^E:" | tee -a "$LOG_FILE"
        exit 1
    fi

    # Check if it says already installed or newly installed
    if echo "$INSTALL_OUTPUT" | grep -q "already the newest version\|is already installed"; then
        log_warning "Zeek is already installed (skipping)"
    elif echo "$INSTALL_OUTPUT" | grep -q "Setting up zeek"; then
        log_success "Zeek installed successfully"
    else
        log_success "Zeek installation completed"
    fi

    # Verify installation
    if [[ -f "$ZEEK_HOME/bin/zeek" ]]; then
        ZEEK_VERSION=$("$ZEEK_HOME/bin/zeek" -v 2>&1 | head -n1)
        log_success "Zeek installation verified: $ZEEK_VERSION"
    else
        log_error "Zeek binary not found after installation"
        exit 1
    fi
}

###############################################################################
# User Account Hardening
###############################################################################

harden_user_account() {
    log "Hardening zeek user account..."

    # Change shell to nologin (more standard than /bin/false)
    if usermod -s /usr/sbin/nologin "$ZEEK_USER"; then
        log_success "Changed shell to /usr/sbin/nologin"
    else
        log_warning "Could not change shell (may already be set)"
    fi

    # Lock the account to prevent password authentication
    if passwd -l "$ZEEK_USER" 2>/dev/null; then
        log_success "Account locked (password authentication disabled)"
    else
        log_warning "Account may already be locked"
    fi

    # Verify account status
    ACCOUNT_STATUS=$(passwd -S "$ZEEK_USER" 2>/dev/null | awk '{print $2}')
    if [[ "$ACCOUNT_STATUS" == "L" ]]; then
        log_success "Verified: Account is locked"
    else
        log_warning "Account status: $ACCOUNT_STATUS"
    fi
}

###############################################################################
# File and Directory Permissions
###############################################################################

fix_directory_permissions() {
    log "Fixing directory permissions and ownership..."

    # Stop Zeek service before changing permissions
    if systemctl is-active --quiet zeek.service; then
        log "Stopping Zeek service..."
        systemctl stop zeek.service
        sleep 2
    fi

    # Create directory structure if missing
    declare -a DIRECTORIES=(
        "$ZEEK_HOME/logs"
        "$ZEEK_HOME/spool"
        "$ZEEK_HOME/var"
    )

    for dir in "${DIRECTORIES[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            log "Created directory: $dir"
        fi
    done

    # Configuration directory - readable by zeek group, owned by root
    if [[ -d "$ZEEK_HOME/etc" ]]; then
        chown -R root:$ZEEK_GROUP "$ZEEK_HOME/etc"
        chmod 750 "$ZEEK_HOME/etc"
        find "$ZEEK_HOME/etc" -type f -exec chmod 640 {} \;
        find "$ZEEK_HOME/etc" -type d -exec chmod 750 {} \;
        log_success "Secured $ZEEK_HOME/etc (root:zeek, 750/640)"
    fi

    # Scripts and policies - readable by zeek group
    if [[ -d "$ZEEK_HOME/share" ]]; then
        chown -R root:$ZEEK_GROUP "$ZEEK_HOME/share"
        chmod 755 "$ZEEK_HOME/share"
        find "$ZEEK_HOME/share" -type d -exec chmod 755 {} \;

        # Make ALL zeekctl scripts executable (including subdirectories like helpers/)
        if [[ -d "$ZEEK_HOME/share/zeekctl/scripts" ]]; then
            find "$ZEEK_HOME/share/zeekctl/scripts" -type f -exec chmod 755 {} \;
        fi

        # Make shell and python scripts executable
        find "$ZEEK_HOME/share" -type f -name "*.sh" -exec chmod 755 {} \;
        find "$ZEEK_HOME/share" -type f -name "*.py" -exec chmod 755 {} \;

        # Set Zeek policy files to readable only
        find "$ZEEK_HOME/share" -type f -name "*.zeek" -exec chmod 644 {} \;
        find "$ZEEK_HOME/share" -type f -name "*.bro" -exec chmod 644 {} \;

        log_success "Secured $ZEEK_HOME/share (root:zeek, zeekctl scripts executable)"
    fi

    # Runtime directories - writable by zeek user
    for dir in logs spool var; do
        if [[ -d "$ZEEK_HOME/$dir" ]]; then
            chown -R $ZEEK_USER:$ZEEK_GROUP "$ZEEK_HOME/$dir"
            chmod 750 "$ZEEK_HOME/$dir"
            log_success "Secured $ZEEK_HOME/$dir (zeek:zeek, 750)"
        fi
    done

    # Binary directory - owned by root, executable by zeek
    if [[ -d "$ZEEK_HOME/bin" ]]; then
        chown -R root:$ZEEK_GROUP "$ZEEK_HOME/bin"
        chmod 755 "$ZEEK_HOME/bin"
        find "$ZEEK_HOME/bin" -type f -executable -exec chmod 755 {} \;
        log_success "Secured $ZEEK_HOME/bin (root:zeek, 755)"
    fi

    # Wrapper script - executable by zeek
    if [[ -f "$ZEEK_HOME/start-zeek.sh" ]]; then
        chown root:$ZEEK_GROUP "$ZEEK_HOME/start-zeek.sh"
        chmod 750 "$ZEEK_HOME/start-zeek.sh"
        log_success "Secured wrapper script (root:zeek, 750)"
    fi
}

verify_zeek_access() {
    log "Verifying zeek user can access required files..."

    # Test config file access
    if sudo -u $ZEEK_USER test -r "$ZEEK_HOME/etc/node.cfg"; then
        log_success "Zeek user can read configuration files"
    else
        log_error "Zeek user CANNOT read configuration files"
        return 1
    fi

    # Test log directory write access
    if sudo -u $ZEEK_USER test -w "$ZEEK_HOME/logs"; then
        log_success "Zeek user can write to logs directory"
    else
        log_error "Zeek user CANNOT write to logs directory"
        return 1
    fi

    # Test spool directory write access
    if sudo -u $ZEEK_USER test -w "$ZEEK_HOME/spool"; then
        log_success "Zeek user can write to spool directory"
    else
        log_error "Zeek user CANNOT write to spool directory"
        return 1
    fi
}

###############################################################################
# Wrapper Script Creation
###############################################################################

create_wrapper_script() {
    log "Creating Zeek wrapper script..."

    # Create with restrictive umask
    (umask 077 && cat > "$ZEEK_HOME/start-zeek.sh" << 'EOF'
#!/bin/bash
# Zeek startup wrapper script
# Monitors Zeek processes and exits if they die (triggers systemd restart)

/opt/zeek/bin/zeekctl deploy

# Keep the service running by monitoring zeek processes
while true; do
    if ! pgrep -f "zeek.*-i" > /dev/null; then
        # Zeek processes died, exit to trigger systemd restart
        exit 1
    fi
    sleep 5
done
EOF
)

    chown root:$ZEEK_GROUP "$ZEEK_HOME/start-zeek.sh"
    chmod 750 "$ZEEK_HOME/start-zeek.sh"
    log_success "Wrapper script created with secure permissions"
}

###############################################################################
# Systemd Service Hardening
###############################################################################

update_systemd_service() {
    log "Updating systemd service configuration..."

    # Detect network interface from current configuration
    INTERFACE=$(grep "^interface=" "$ZEEK_HOME/etc/node.cfg" 2>/dev/null | cut -d= -f2 | tr -d ' ')
    if [[ -z "$INTERFACE" ]]; then
        INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    fi

    if [[ -z "$INTERFACE" ]]; then
        log_error "Could not detect network interface"
        return 1
    fi

    log "Detected interface: $INTERFACE"

    # Create hardened systemd service
    cat > /etc/systemd/system/zeek.service << EOF
[Unit]
Description=Zeek Network Security Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$ZEEK_USER
Group=$ZEEK_GROUP
WorkingDirectory=$ZEEK_HOME

# Network interface management
ExecStartPre=/usr/sbin/ip link set $INTERFACE promisc on
ExecStart=$ZEEK_HOME/start-zeek.sh
ExecStop=$ZEEK_HOME/bin/zeekctl stop
ExecStopPost=/usr/sbin/ip link set $INTERFACE promisc off

# Restart configuration
Restart=on-failure
RestartSec=10

# Security Hardening
# ==================

# Process Restrictions
NoNewPrivileges=true
PrivateTmp=true
LockPersonality=true

# Filesystem Protection
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$ZEEK_HOME/logs $ZEEK_HOME/spool $ZEEK_HOME/var
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true

# Execution Restrictions
RestrictRealtime=true
RestrictNamespaces=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=false

# Network Configuration
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET

# Capabilities (MINIMAL - only what's needed for packet capture)
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

# System Call Filtering
SystemCallFilter=@system-service @network-io @io-event
SystemCallFilter=~@privileged @resources @obsolete @debug @mount @cpu-emulation @module @raw-io @reboot @swap
SystemCallErrorNumber=EPERM

# Resource Limits
LimitNOFILE=65536
LimitNPROC=512

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zeek

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 /etc/systemd/system/zeek.service
    chown root:root /etc/systemd/system/zeek.service
    log_success "Created hardened systemd service file"

    # Reload systemd
    systemctl daemon-reload
    log_success "Reloaded systemd daemon"
}

###############################################################################
# ZeekControl Configuration
###############################################################################

configure_zeekctl() {
    log "Configuring ZeekControl for non-root operation..."

    ZEEKCTL_CFG="$ZEEK_HOME/etc/zeekctl.cfg"

    if [[ -f "$ZEEKCTL_CFG" ]]; then
        # Backup original
        cp "$ZEEKCTL_CFG" "${ZEEKCTL_CFG}.bak.$(date +%s)"

        # Set log directory with proper permissions
        if ! grep -q "^LogDir" "$ZEEKCTL_CFG"; then
            echo "LogDir = $ZEEK_HOME/logs" >> "$ZEEKCTL_CFG"
        fi

        # Set spool directory
        if ! grep -q "^SpoolDir" "$ZEEKCTL_CFG"; then
            echo "SpoolDir = $ZEEK_HOME/spool" >> "$ZEEKCTL_CFG"
        fi

        log_success "Configured ZeekControl settings"
    fi
}

###############################################################################
# Capability Verification
###############################################################################

verify_capabilities() {
    log "Verifying capabilities on Zeek binary..."

    ZEEK_BIN="$ZEEK_HOME/bin/zeek"

    # Check current capabilities
    CURRENT_CAPS=$(getcap "$ZEEK_BIN" 2>/dev/null)

    if [[ -z "$CURRENT_CAPS" ]]; then
        log_warning "No capabilities set on Zeek binary, setting them now..."

        # Install libcap2-bin if needed
        if ! command -v setcap &> /dev/null; then
            apt-get update > /dev/null 2>&1
            apt-get install -y libcap2-bin > /dev/null 2>&1
        fi

        # Set capabilities
        if setcap cap_net_raw,cap_net_admin=eip "$ZEEK_BIN"; then
            log_success "Set capabilities on Zeek binary"
        else
            log_error "Failed to set capabilities"
            return 1
        fi
    else
        log_success "Capabilities already set: $CURRENT_CAPS"
    fi

    # Verify capabilities
    CAPS=$(getcap "$ZEEK_BIN")
    if [[ "$CAPS" =~ cap_net_raw && "$CAPS" =~ cap_net_admin ]]; then
        log_success "Verified: Required capabilities are present"
    else
        log_error "Capability verification failed"
        return 1
    fi
}

###############################################################################
# Service Testing
###############################################################################

test_service_startup() {
    log "Testing Zeek service with new configuration..."

    # Start service
    log "Starting Zeek service..."
    if systemctl start zeek.service; then
        log_success "Service start command completed"
    else
        log_error "Service failed to start"
        systemctl status zeek.service --no-pager | tee -a "$LOG_FILE"
        return 1
    fi

    # Wait for service to initialize
    sleep 10

    # Check if service is active
    if systemctl is-active --quiet zeek.service; then
        log_success "Service is running"
    else
        log_error "Service is not running"
        journalctl -u zeek.service -n 50 --no-pager | tee -a "$LOG_FILE"
        return 1
    fi

    # Verify process owner
    PROC_USER=$(ps aux | grep "[z]eek.*-i" | awk '{print $1}' | head -n1)
    if [[ -z "$PROC_USER" ]]; then
        log_error "No Zeek processes found"
        return 1
    fi

    if [[ "$PROC_USER" == "$ZEEK_USER" ]]; then
        log_success "Zeek is running as '$ZEEK_USER' user (not root)"
    else
        log_error "Zeek is running as '$PROC_USER' (expected '$ZEEK_USER')"
        return 1
    fi

    # Wait for logs to be created
    sleep 5

    # Check if logs are being written
    if [[ -f "$ZEEK_HOME/logs/current/conn.log" ]]; then
        log_success "Zeek is writing logs successfully"
    else
        log_warning "Logs not yet created (may need more time)"
    fi
}

###############################################################################
# Security Audit
###############################################################################

perform_security_audit() {
    log "Performing security audit..."

    echo "" | tee -a "$LOG_FILE"
    echo "========================================" | tee -a "$LOG_FILE"
    echo "ZEEK SECURITY AUDIT REPORT" | tee -a "$LOG_FILE"
    echo "========================================" | tee -a "$LOG_FILE"

    # Check user account
    echo "" | tee -a "$LOG_FILE"
    echo "User Account:" | tee -a "$LOG_FILE"
    id $ZEEK_USER | tee -a "$LOG_FILE"
    echo "Shell: $(getent passwd $ZEEK_USER | cut -d: -f7)" | tee -a "$LOG_FILE"
    echo "Status: $(passwd -S $ZEEK_USER 2>/dev/null | awk '{print $2}')" | tee -a "$LOG_FILE"

    # Check file permissions
    echo "" | tee -a "$LOG_FILE"
    echo "Directory Permissions:" | tee -a "$LOG_FILE"
    for dir in etc share bin logs spool var; do
        if [[ -d "$ZEEK_HOME/$dir" ]]; then
            echo "  $dir: $(stat -c '%a %U:%G' $ZEEK_HOME/$dir)" | tee -a "$LOG_FILE"
        fi
    done

    # Check capabilities
    echo "" | tee -a "$LOG_FILE"
    echo "Binary Capabilities:" | tee -a "$LOG_FILE"
    getcap "$ZEEK_HOME/bin/zeek" | tee -a "$LOG_FILE"

    # Check service configuration
    echo "" | tee -a "$LOG_FILE"
    echo "Service Configuration:" | tee -a "$LOG_FILE"
    systemctl show zeek.service --property=User --property=Group --property=CapabilityBoundingSet | tee -a "$LOG_FILE"

    # Check running processes
    echo "" | tee -a "$LOG_FILE"
    echo "Running Processes:" | tee -a "$LOG_FILE"
    ps aux | grep "[z]eek" | awk '{print $1, $2, $11}' | tee -a "$LOG_FILE"

    echo "" | tee -a "$LOG_FILE"
    echo "========================================" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
}

###############################################################################
# Cleanup
###############################################################################

cleanup() {
    # Secure log file permissions
    if [[ -f "$LOG_FILE" ]]; then
        chmod 640 "$LOG_FILE"
        chown root:adm "$LOG_FILE"
    fi
}

trap cleanup EXIT

###############################################################################
# Summary Report
###############################################################################

print_summary() {
    # Get Zeek version
    local ZEEK_VER="N/A"
    if [[ -f "$ZEEK_HOME/bin/zeek" ]]; then
        ZEEK_VER=$("$ZEEK_HOME/bin/zeek" -v 2>&1 | head -n1 | awk '{print $3}')
    fi

    cat << EOF

${GREEN}════════════════════════════════════════════════════════════${NC}
${GREEN}  Zeek Installation & Security Hardening Complete!${NC}
${GREEN}════════════════════════════════════════════════════════════${NC}

${BLUE}Installation Summary:${NC}
  • Zeek Version: $ZEEK_VER
  • Installation Path: $ZEEK_HOME
  • Configuration: $ZEEK_HOME/etc

${BLUE}Security Improvements Applied:${NC}
  ✓ Service now runs as '$ZEEK_USER' user (NOT root)
  ✓ User account locked (no password authentication)
  ✓ Shell set to /usr/sbin/nologin
  ✓ File permissions properly configured
  ✓ Capabilities reduced to minimum (CAP_NET_RAW, CAP_NET_ADMIN)
  ✓ Systemd service hardened with security directives
  ✓ System call filtering enabled
  ✓ Filesystem protection enabled
  ✓ Namespace restrictions applied

${BLUE}Directory Security:${NC}
  • Config: $ZEEK_HOME/etc (root:zeek, 750/640)
  • Scripts: $ZEEK_HOME/share (root:zeek, 755/644)
  • Logs: $ZEEK_HOME/logs (zeek:zeek, 750)
  • Spool: $ZEEK_HOME/spool (zeek:zeek, 750)
  • Runtime: $ZEEK_HOME/var (zeek:zeek, 750)

${BLUE}Capability Configuration:${NC}
  • CAP_NET_RAW: Enabled (packet capture)
  • CAP_NET_ADMIN: Enabled (interface management)
  • All other capabilities: Removed

${BLUE}Systemd Hardening:${NC}
  ✓ ProtectSystem=strict
  ✓ ProtectHome=true
  ✓ ProtectKernel*=true
  ✓ NoNewPrivileges=true
  ✓ SystemCallFilter enabled
  ✓ RestrictNamespaces=true
  ✓ MemoryDenyWriteExecute=false (required by Zeek)

${BLUE}Service Status:${NC}
  • Status: $(systemctl is-active zeek.service)
  • Process Owner: $(ps aux | grep "[z]eek.*-i" | awk '{print $1}' | head -n1)
  • PID: $(pgrep -f "zeek.*-i" | head -n1)

${BLUE}Verification Commands:${NC}
  • Check service: sudo systemctl status zeek.service
  • View logs: sudo tail -f $ZEEK_HOME/logs/current/conn.log
  • Check user: id $ZEEK_USER
  • Verify caps: getcap $ZEEK_HOME/bin/zeek
  • View journal: sudo journalctl -u zeek.service -f
  • Check version: zeek -v

${BLUE}Security Notes:${NC}
  • Zeek now operates with minimal privileges
  • All sensitive operations use capabilities, not root
  • Service is hardened against common attack vectors
  • Logs are protected from unauthorized access
  • Configuration changes require root privileges

${BLUE}Audit Log:${NC}
  • Full log: $LOG_FILE

${GREEN}════════════════════════════════════════════════════════════${NC}

EOF
}

###############################################################################
# Main Execution Flow
###############################################################################

main() {
    clear
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║    Zeek Installation & Security Hardening Script      ║${NC}"
    echo -e "${BLUE}║    Installs and Secures Zeek IDS                      ║${NC}"
    echo -e "${BLUE}║                                                        ║${NC}"
    echo -e "${BLUE}║    ${YELLOW}For Ubuntu 24.04 LTS Only${BLUE}                       ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""

    log "Starting Zeek installation and security hardening..."

    # Phase 1: Prerequisites
    log "Phase 1: Prerequisite Checks"
    check_root
    check_zeek_user_exists
    echo ""

    # Phase 2: Installation
    log "Phase 2: Zeek Installation"
    install_zeek
    echo ""

    # Phase 3: User Hardening
    log "Phase 3: User Account Hardening"
    harden_user_account
    echo ""

    # Phase 4: File Permissions
    log "Phase 4: File and Directory Permissions"
    fix_directory_permissions
    verify_zeek_access
    echo ""

    # Phase 5: Capabilities
    log "Phase 5: Capability Verification"
    verify_capabilities
    echo ""

    # Phase 6: ZeekControl Configuration
    log "Phase 6: ZeekControl Configuration"
    configure_zeekctl
    echo ""

    # Phase 7: Wrapper Script
    log "Phase 7: Wrapper Script Creation"
    create_wrapper_script
    echo ""

    # Phase 8: Systemd Service
    log "Phase 8: Systemd Service Hardening"
    update_systemd_service
    echo ""

    # Phase 9: Testing
    log "Phase 9: Service Startup Test"
    test_service_startup
    echo ""

    # Phase 10: Audit
    log "Phase 10: Security Audit"
    perform_security_audit
    echo ""

    # Phase 11: Summary
    print_summary

    log_success "Installation and security hardening completed successfully!"
}

# Run main function
main "$@"
