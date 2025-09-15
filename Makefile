.PHONY: all help run attack stop-attack clean

all: help

help:
	@echo "Available commands:"
	@echo "  make run          - Start the Python controller (needs sudo)"
	@echo "  make attack       - Start the test UDP flood attack (needs sudo)"
	@echo "  make stop-attack  - Stop the test attack (needs sudo)"
	@echo "  make clean        - Remove all log files"

run:
	@echo "[*] Starting the XDP controller..."
	sudo python3 controller.py

attack:
	@echo "[*] Starting UDP flood test..."
	sudo ./scripts/start_attack.sh

stop-attack:
	@echo "[*] Stopping UDP flood test..."
	sudo ./scripts/stop_attack.sh

clean:
	@echo "[*] Cleaning up log files..."
	@rm -rf logs/
	@echo "[*] Done."