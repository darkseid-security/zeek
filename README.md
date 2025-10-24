# Zeek IDS Installation and Testing

This repository contains a comprehensive installation script for Zeek Network Security Monitor on Ubuntu systems.

## Overview

Zeek (formerly known as Bro) is a powerful network analysis framework that is much different from a typical IDS. This script automates the complete installation, configuration, and testing of Zeek IDS on Ubuntu 25.04 systems.

## Features

- Automated installation from OpenSUSE security repository
- Automatic network interface detection and configuration
- Systemd service integration for automatic startup
- Comprehensive testing suite that verifies:
  - Service status
  - Process execution
  - Log generation
  - Traffic capture
- Color-coded output for easy monitoring
- Built-in health checks and validation

## Prerequisites

- Ubuntu 25.04 (xUbuntu_25.04)
- Root/sudo access
- Active network connection
- Network interface for monitoring

## Installation

### Quick Start

```bash
sudo bash zeek_install.sh
```

### What the Script Does

The installation process consists of 10 steps:

1. **System Update** - Updates all system packages
2. **Repository Addition** - Adds Zeek security repository
3. **GPG Key** - Imports repository signing key
4. **Package List Update** - Refreshes available packages
5. **Zeek Installation** - Installs Zeek and dependencies
6. **Interface Detection** - Automatically detects primary network interface
7. **Configuration** - Configures Zeek to monitor detected interface
8. **Wrapper Script** - Creates management script for Zeek
9. **Service Setup** - Creates and enables systemd service
10. **Verification** - Tests that Zeek is running correctly

### Post-Installation Testing

The script automatically:
- Generates test HTTP/HTTPS traffic
- Performs DNS queries
- Verifies log file creation
- Displays sample log entries
- Shows service status

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

- Zeek runs as root to capture network traffic
- Monitor disk space - logs can grow large
- Consider log rotation policies
- Review Zeek's security policies regularly
- Keep Zeek updated with security patches

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
