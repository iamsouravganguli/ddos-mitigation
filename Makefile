# Makefile for the XDP DDoS mitigation tool

# Phony targets are not actual files. This prevents conflicts if a file with the same name as a target exists.
.PHONY: all help run attack stop-attack clean

# The default target when you just run `make`. It will run the `help` target.
all: help

# Displays the available commands.
help:
	@echo "Available commands:"
	@echo "  make run          - Start the Python controller (needs sudo)"
	@echo "  make attack       - Start the test UDP flood attack (needs sudo)"
	@echo "  make stop-attack  - Stop the test attack (needs sudo)"
	@echo "  make clean        - Remove all log files"

# Starts the Python controller, which loads and manages the XDP program.
run:
	@echo "[*] Starting the XDP controller..."
	sudo python3 controller.py

# Starts a test UDP flood attack using the `hping3` tool.
attack:
	@echo "[*] Starting UDP flood test..."
	sudo ./scripts/start_attack.sh

# Stops the test UDP flood attack.
stop-attack:
	@echo "[*] Stopping UDP flood test..."
	sudo ./scripts/stop_attack.sh

# Removes log files created by the controller.
clean:
	@echo "[*] Cleaning up log files..."
	@rm -rf logs/
	@echo "[*] Done."
