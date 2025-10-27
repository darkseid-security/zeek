# Zeek IDS Installation and Security Hardening

This repository contains scripts for secure installation and configuration of Zeek Network Security Monitor on Ubuntu systems with comprehensive security hardening.

## Overview

Zeek (formerly known as Bro) is a powerful network analysis framework that is much different from a typical IDS. These scripts automate the complete installation, configuration, and security hardening of Zeek IDS with proper privilege separation and minimal capabilities.

## Features

- **Two-script workflow** for easy deployment
- Dedicated service account with locked credentials
- Installation from OpenSUSE security repository
- Automatic network interface detection and configuration
- Linux capabilities instead of root privileges (CAP_NET_RAW, CAP_NET_ADMIN)
- Comprehensive systemd security hardening
- Proper file permissions and ownership
- System call filtering and namespace restrictions
- Automated testing and verification
- Color-coded output for easy monitoring

## Prerequisites

- Ubuntu 25.04 (xUbuntu_25.04) or compatible Debian-based distribution
- Root/sudo access
- Active network connection
- Network interface for monitoring

## Installation Workflow

The installation process is split into **two scripts** for security and modularity:

### Step 1: Create Service Account

First, create a dedicated system account for running Zeek:

```bash
sudo bash setup_zeek_user.sh
```

**What it does:**
- Creates system user and group `zeek`
- Sets shell to `/usr/sbin/nologin` (prevents login)
- Locks account (disables password authentication)
- Verifies account creation

### Step 2: Install and Harden Zeek

Install Zeek and apply comprehensive security hardening:

```bash
sudo bash harden_zeek_security.sh
```

**What it does:**
1. **System Update** - Updates all system packages
2. **Repository Addition** - Adds Zeek security repository with GPG verification
3. **Zeek Installation** - Installs Zeek and dependencies
4. **User Hardening** - Ensures zeek account is properly locked
5. **File Permissions** - Sets secure ownership and permissions
6. **Capabilities** - Sets Linux capabilities for non-root packet capture
7. **ZeekControl Config** - Configures ZeekControl paths
8. **Systemd Service** - Creates hardened systemd service
9. **Service Testing** - Starts and verifies Zeek is running correctly
10. **Security Audit** - Performs comprehensive security audit

## Security Features

### Privilege Separation

- **Non-root operation**: Zeek runs as unprivileged `zeek` user
- **Locked account**: Cannot be used for interactive login
- **No password**: Password authentication disabled
- **Minimal capabilities**: Only CAP_NET_RAW and CAP_NET_ADMIN

### File Permission Model

```
/opt/zeek/
├── bin/              # Binaries (root:zeek, 755)
├── etc/              # Configuration (root:zeek, 750/640) - read-only for zeek
├── logs/             # Log files (zeek:zeek, 750) - writable by zeek
├── spool/            # Spool directory (zeek:zeek, 750) - writable by zeek
├── var/              # Runtime data (zeek:zeek, 750) - writable by zeek
├── share/            # Scripts/policies (root:zeek, 755/644)
└── start-zeek.sh     # Wrapper script (root:zeek, 750)
```

### Systemd Security Hardening

The systemd service includes comprehensive security directives:

- **Filesystem Protection**
  - `ProtectSystem=strict` - Read-only system directories
  - `ProtectHome=true` - No access to user home directories
  - `ProtectKernelTunables=true` - Kernel tunables protected
  - `ProtectKernelModules=true` - Cannot load kernel modules
  - `ProtectKernelLogs=true` - Kernel logs protected
  - `ProtectControlGroups=true` - cgroups protected

- **Process Restrictions**
  - `NoNewPrivileges=true` - Prevents privilege escalation
  - `PrivateTmp=true` - Private /tmp directory
  - `LockPersonality=true` - Prevents personality changes
  - `RestrictRealtime=true` - No realtime scheduling
  - `RestrictNamespaces=true` - Namespace restrictions
  - `RestrictSUIDSGID=true` - Cannot create SUID/SGID files

- **Capability Bounding**
  - Only CAP_NET_RAW and CAP_NET_ADMIN allowed
  - All other capabilities removed

- **System Call Filtering**
  - Allows: @system-service, @network-io, @io-event
  - Denies: @privileged, @resources, @obsolete, @debug, @mount, etc.

- **Network Configuration**
  - `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET`

## File Locations

- **Zeek Installation**: `/opt/zeek/`
- **Configuration**: `/opt/zeek/etc/node.cfg`
- **Logs**: `/opt/zeek/logs/current/`
- **Wrapper Script**: `/opt/zeek/start-zeek.sh`
- **Systemd Service**: `/etc/systemd/system/zeek.service`

## Usage

### Service Management

```bash
# Check service status
sudo systemctl status zeek

# Start Zeek
sudo systemctl start zeek

# Stop Zeek
sudo systemctl stop zeek

# Restart Zeek
sudo systemctl restart zeek

# View service logs
sudo journalctl -u zeek -f
```

### Monitoring Logs

Zeek generates various log files for different types of network activity:

```bash
# Connection logs (all network connections)
tail -f /opt/zeek/logs/current/conn.log

# HTTP traffic
tail -f /opt/zeek/logs/current/http.log

# DNS queries
tail -f /opt/zeek/logs/current/dns.log

# SSH connections
tail -f /opt/zeek/logs/current/ssh.log

# View all available logs
ls -lh /opt/zeek/logs/current/
```

### Manual Control

```bash
# Deploy Zeek configuration
sudo /opt/zeek/bin/zeekctl deploy

# Check Zeek status
sudo /opt/zeek/bin/zeekctl status

# Stop Zeek
sudo /opt/zeek/bin/zeekctl stop
```

## Log Files

Zeek generates comprehensive logs in tab-separated format:

- **conn.log** - All network connections
- **dns.log** - DNS queries and responses
- **http.log** - HTTP requests and responses
- **ssl.log** - SSL/TLS connections
- **ssh.log** - SSH connections
- **files.log** - File transfers
- **weird.log** - Unusual network activity
- **notice.log** - Zeek notices and alerts

## Troubleshooting

### Service Won't Start

```bash
# Check service status
sudo systemctl status zeek

# View detailed logs
sudo journalctl -u zeek -n 50

# Check if interface is correct
cat /opt/zeek/etc/node.cfg | grep interface

# Manually test Zeek
sudo /opt/zeek/bin/zeekctl deploy
```

### No Logs Being Generated

```bash
# Check if Zeek processes are running
ps aux | grep zeek

# Verify network interface is up
ip link show

# Check permissions
ls -la /opt/zeek/logs/
```

### Change Network Interface

```bash
# Edit configuration
sudo nano /opt/zeek/etc/node.cfg

# Find and modify the line:
# interface=<your-interface-name>

# Restart Zeek
sudo systemctl restart zeek
```

## Security Considerations

- **Zeek runs as non-root** - Uses dedicated `zeek` user with minimal capabilities
- **Locked service account** - Cannot be used for interactive login
- **Read-only configuration** - Config files owned by root, preventing tampering
- **Systemd hardening** - Comprehensive security restrictions applied
- **Syscall filtering** - Only necessary system calls allowed
- **Monitor disk space** - Logs can grow large, rotation configured
- **Review policies** - Regularly review Zeek's security policies
- **Keep updated** - Apply security patches promptly

## Audit Logs

The scripts maintain detailed audit logs:

- **Service Account Creation**: `/var/log/zeek_user_setup.log`
- **Installation and Hardening**: `/var/log/zeek_security_hardening.log`
- **Systemd Journal**: `journalctl -u zeek.service`

## Verification Commands

After installation, verify the security configuration:

```bash
# Check service status
sudo systemctl status zeek.service

# Verify process owner (should be 'zeek', not 'root')
ps aux | grep zeek

# Check file permissions
ls -la /opt/zeek/

# Verify capabilities on binary
getcap /opt/zeek/bin/zeek

# Check user account status
id zeek
passwd -S zeek

# View systemd security settings
systemctl show zeek.service --property=CapabilityBoundingSet
systemctl show zeek.service --property=User
```

## Version Information

```bash
# Check Zeek version
zeek -v

# View installed packages
dpkg -l | grep zeek
```

## Additional Resources

- [Zeek Official Documentation](https://docs.zeek.org/)
- [Zeek Script Reference](https://docs.zeek.org/en/master/script-reference/)
- [Zeek Package Manager](https://packages.zeek.org/)

## License

This installation script is provided as-is for educational and security monitoring purposes.

## Contributing

Feel free to submit issues or pull requests for improvements to the installation script.

## Support

For Zeek-specific issues, consult the [official Zeek documentation](https://docs.zeek.org/) or community forums.

---

## Migration from Old Installation Method

If you previously used `zeek_install.sh`, note that it has been **deprecated** in favor of the new two-script workflow:

**Old Method (Deprecated):**
- `zeek_install.sh` - All-in-one installation (runs as root, less secure)

**New Method (Recommended):**
1. `setup_zeek_user.sh` - Create service account
2. `harden_zeek_security.sh` - Install and harden Zeek

**Benefits of New Approach:**
- Better privilege separation
- More secure default configuration
- Modular and maintainable
- Comprehensive security hardening
- Follows security best practices

To migrate from old installation:
```bash
# Stop old service
sudo systemctl stop zeek

# Run new scripts
sudo bash setup_zeek_user.sh
sudo bash harden_zeek_security.sh

# The new scripts will reconfigure existing installation with proper security
```
