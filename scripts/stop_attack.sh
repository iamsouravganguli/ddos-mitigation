#!/bin/bash

# This script stops all running hping3 processes.
# It is used to halt the denial-of-service (DoS) attack simulation
# started by the start_attack.sh script.

echo "[*] Stopping all hping3 attacks..."

# pkill is used to find and send a termination signal to processes
# matching the name "hping3". sudo is required to stop processes
# that were started with sudo.
sudo pkill hping3
