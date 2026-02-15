#!/usr/bin/env bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'  # reset/no color

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