#!/bin/bash

# Zeek IDS Complete Installation and Testing Script
# This script installs Zeek from OpenSUSE repo and tests it thoroughly

set -e  # Exit on error

echo "=================================================="
echo "Zeek IDS Installation and Testing Script"
echo "=================================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

echo -e "${YELLOW}[1/10] Updating system packages...${NC}"
apt update
apt upgrade -y
sleep 2

echo ""
echo -e "${YELLOW}[2/10] Adding Zeek repository...${NC}"
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_25.04/ /' | tee /etc/apt/sources.list.d/security:zeek.list
sleep 1

echo ""
echo -e "${YELLOW}[3/10] Adding repository GPG key...${NC}"
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_25.04/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sleep 1

echo ""
echo -e "${YELLOW}[4/10] Updating package lists...${NC}"
apt update
sleep 2

echo ""
echo -e "${YELLOW}[5/10] Installing Zeek...${NC}"
apt install -y zeek
sleep 3

echo ""
echo -e "${YELLOW}[6/10] Detecting network interface...${NC}"
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -z "$INTERFACE" ]; then
    INTERFACE="eth0"
fi
echo "Network interface detected: $INTERFACE"
sleep 1

echo ""
echo -e "${YELLOW}[7/10] Configuring Zeek network interface...${NC}"
sed -i "s/^interface=.*/interface=$INTERFACE/" /opt/zeek/etc/node.cfg
echo "Interface set to: $INTERFACE"
sleep 1

echo ""
echo -e "${YELLOW}[8/10] Creating Zeek wrapper script...${NC}"
cat > /opt/zeek/start-zeek.sh << 'EOF'
#!/bin/bash
/opt/zeek/bin/zeekctl deploy
# Keep the service running by monitoring zeek processes
while true; do
  if ! pgrep -f "zeek.*-i" > /dev/null; then
    exit 1
  fi
  sleep 5
done
EOF

chmod +x /opt/zeek/start-zeek.sh
echo "Wrapper script created and made executable"
sleep 1

echo ""
echo -e "${YELLOW}[8b/10] Creating systemd service file...${NC}"
cat > /etc/systemd/system/zeek.service << 'EOF'
[Unit]
Description=Zeek Network Security Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/zeek
ExecStart=/opt/zeek/start-zeek.sh
ExecStop=/opt/zeek/bin/zeekctl stop
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

echo "Systemd service file created"
sleep 1

echo ""
echo -e "${YELLOW}[9/10] Enabling and starting Zeek service...${NC}"
systemctl daemon-reload
systemctl enable zeek
systemctl start zeek
sleep 5

echo ""
echo -e "${YELLOW}[10/10] Verifying Zeek is running...${NC}"
sleep 5  # Give Zeek time to fully start

if systemctl is-active --quiet zeek; then
    echo -e "${GREEN}✓ Zeek service is running${NC}"
else
    echo -e "${RED}✗ Zeek service failed to start${NC}"
    systemctl status zeek
    exit 1
fi

echo ""
echo "Checking Zeek processes..."
PROC_COUNT=$(ps aux | grep -c "zeek.*-i")
if [ $PROC_COUNT -gt 0 ]; then
    echo -e "${GREEN}✓ Found Zeek processes running on $INTERFACE${NC}"
else
    echo -e "${RED}✗ No Zeek processes found${NC}"
    ps aux | grep zeek
    exit 1
fi
sleep 3

echo ""
echo "=================================================="
echo "Testing Zeek Log Generation"
echo "=================================================="
echo ""

# Clean old logs and wait for fresh ones
echo -e "${YELLOW}Waiting for log directory to initialize...${NC}"
sleep 3

echo ""
echo -e "${YELLOW}Generating test traffic...${NC}"
echo "  - Testing HTTP connection..."
curl -s http://example.com > /dev/null 2>&1
sleep 3

echo "  - Testing HTTPS connection..."
curl -s https://example.com > /dev/null 2>&1
sleep 3

echo "  - Testing DNS query..."
nslookup example.com > /dev/null 2>&1
sleep 3

echo "  - Testing additional HTTP request..."
curl -s http://www.google.com > /dev/null 2>&1
sleep 3

echo ""
echo "=================================================="
echo "Zeek Log Analysis"
echo "=================================================="
echo ""

LOG_DIR="/opt/zeek/logs/current"

# Check conn.log
echo -e "${YELLOW}Checking conn.log...${NC}"
if [ -f "$LOG_DIR/conn.log" ]; then
    echo -e "${GREEN}✓ conn.log exists${NC}"
    CONN_ENTRIES=$(grep -v "^#" "$LOG_DIR/conn.log" | wc -l)
    echo "  Entries: $CONN_ENTRIES"
    echo "  Sample entries:"
    grep -v "^#" "$LOG_DIR/conn.log" | tail -3 | sed 's/\t/ | /g' | sed 's/^/    /'
else
    echo -e "${RED}✗ conn.log not found${NC}"
fi

echo ""

# Check http.log
echo -e "${YELLOW}Checking http.log...${NC}"
if [ -f "$LOG_DIR/http.log" ]; then
    echo -e "${GREEN}✓ http.log exists${NC}"
    HTTP_ENTRIES=$(grep -v "^#" "$LOG_DIR/http.log" 2>/dev/null | wc -l)
    echo "  Entries found: $HTTP_ENTRIES"
    if [ $HTTP_ENTRIES -gt 0 ]; then
        echo "  Sample entries:"
        grep -v "^#" "$LOG_DIR/http.log" | head -3 | cut -f1-7 | while IFS=$'\t' read -r ts uid orig dst sport dport host; do
            echo "    [$(date -d @${ts} '+%H:%M:%S')] $host (${orig}:${sport} -> ${dst}:${dport})"
        done
    fi
else
    echo -e "${YELLOW}~ http.log not yet created (may appear after HTTP traffic)${NC}"
fi

echo ""

# Check dns.log
echo -e "${YELLOW}Checking dns.log...${NC}"
if [ -f "$LOG_DIR/dns.log" ]; then
    echo -e "${GREEN}✓ dns.log exists${NC}"
    DNS_ENTRIES=$(grep -v "^#" "$LOG_DIR/dns.log" 2>/dev/null | wc -l)
    echo "  Entries found: $DNS_ENTRIES"
    if [ $DNS_ENTRIES -gt 0 ]; then
        echo "  Sample entries:"
        grep -v "^#" "$LOG_DIR/dns.log" | head -3 | cut -f1,6 | while IFS=$'\t' read -r ts query; do
            echo "    [$(date -d @${ts} '+%H:%M:%S')] Query: $query"
        done
    fi
else
    echo -e "${YELLOW}~ dns.log not yet created (may appear after DNS queries)${NC}"
fi

echo ""

# Check ssh.log
echo -e "${YELLOW}Checking ssh.log...${NC}"
if [ -f "$LOG_DIR/ssh.log" ]; then
    echo -e "${GREEN}✓ ssh.log exists${NC}"
    SSH_ENTRIES=$(grep -v "^#" "$LOG_DIR/ssh.log" 2>/dev/null | wc -l)
    echo "  Entries: $SSH_ENTRIES"
else
    echo -e "${YELLOW}~ ssh.log not yet created${NC}"
fi

echo ""
echo "=================================================="
echo "Zeek Status Summary"
echo "=================================================="
echo ""

systemctl status zeek --no-pager | head -10

echo ""
echo "Log directory contents:"
ls -lh "$LOG_DIR" | grep -v "^total" | grep -v "^d" | awk '{print "  " $9 " (" $5 ")"}'

echo ""
echo "=================================================="
echo -e "${GREEN}Installation and testing complete!${NC}"
echo "=================================================="
echo ""
echo "Monitor logs in real-time with:"
echo "  tail -f /opt/zeek/logs/current/conn.log"
echo "  tail -f /opt/zeek/logs/current/http.log"
echo "  tail -f /opt/zeek/logs/current/dns.log"
echo ""
echo "Check service status:"
echo "  sudo systemctl status zeek"
echo ""
echo "View Zeek version:"
echo "  zeek -v"
echo ""