# controller.py
#
# This script acts as a controller for an XDP-based DDoS mitigation program.
# It provides an interactive shell to manage whitelists and blocklists,
# monitors traffic for attack patterns, and sends alerts via Telegram
# when an attack is automatically mitigated.

# --- Standard and Third-Party Library Imports ---
import os
import time
import socket
import struct
import asyncio
import threading
import ctypes
from datetime import datetime
from bcc import BPF  # BPF Compiler Collection for interacting with eBPF programs
from dotenv import load_dotenv  # For loading environment variables from a .env file
import telegram  # Python wrapper for the Telegram Bot API

# --- Load Environment Variables ---
# Loads credentials and configuration from a .env file for security and flexibility.
load_dotenv()
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# --- Global Configuration ---
IFACE = "eth0"  # Network interface to attach the XDP program to.
LOG_DIR = "logs"  # Directory to store event logs.
LOG_FILE = os.path.join(LOG_DIR, "events.log") # File for logging auto-blocked IPs.
ARCHIVE_DIR = os.path.join(LOG_DIR, "archive") # Directory for archiving old logs (not used in this script but good practice).

# Ensure the log directory exists.
os.makedirs(ARCHIVE_DIR, exist_ok=True)

# --- Telegram Bot Initialization ---
# Initialize the Telegram bot if a token and chat ID are provided.
# This allows the script to send real-time alerts.
bot = None
if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
    try:
        bot = telegram.Bot(token=TELEGRAM_BOT_TOKEN)
        print("[*] Telegram bot initialized successfully.")
    except Exception as e:
        print(f"[!] Warning: Could not initialize Telegram bot. Alerts will be disabled. Error: {e}")
else:
    print("[!] Warning: Telegram credentials not found in .env file. Alerts will be disabled.")

def send_telegram_alert(ip_addr, packet_count):
    """
    Asynchronously sends a formatted alert message to a Telegram chat.
    Handles cases where an asyncio event loop might already be running.
    """
    if not bot: return # Do nothing if the bot is not initialized.

    async def send_async():
        """Sends the message using the async bot methods."""
        try:
            message = (
                f"🚨 **DDoS Attack Mitigated** 🚨\n\n"
                f"Blocked IP Address: `{ip_addr}`\n"
                f"Reason: Exceeded packet threshold\n"
                f"Packet Count at Block: `{packet_count}`\n"
                f"Timestamp: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
            )
            # Sends the message using the configured bot and chat ID.
            await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message, parse_mode='Markdown')
            print(f"[*] Telegram alert sent for IP: {ip_addr}")
        except Exception as e:
            print(f"[!] Failed to send Telegram alert: {e}")

    # This logic handles sending the async message from a synchronous context.
    try:
        asyncio.run(send_async())
    except RuntimeError:  # Catches error if an event loop is already running.
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(send_async())

# --- BPF Program Loading ---
# Compiles the C code, loads the XDP function, and attaches it to the network interface.
try:
    print("[*] Compiling and loading BPF program...")
    # The BPF object from bcc compiles the source file.
    b = BPF(src_file="xdp_ddos.c", cflags=["-Wno-macro-redefined"])
    # Load the specific function 'xdp_ddos_prog' as an XDP type program.
    fn = b.load_func("xdp_ddos_prog", BPF.XDP)
    print(f"[*] Attaching XDP program to interface {IFACE}...")
    # Attach the loaded function to the specified network interface.
    b.attach_xdp(IFACE, fn, 0)
except Exception as e:
    print(f"[!] Failed to initialize BPF: {e}")
    exit(1)

# --- BPF Map Management Functions ---
def ip_to_key(ip_str):
    """
    Converts a standard IPv4 address string into an integer format
    suitable for use as a key in BPF maps.
    """
    # socket.inet_aton converts string IP to bytes.
    ip_bytes = socket.inet_aton(ip_str)
    # struct.unpack converts bytes to an integer.
    ip_int = struct.unpack("I", ip_bytes)[0]
    # Creates a key structure that the BPF map expects.
    return b["whitelist"].Key(ip_int)

def manage_ip_list(map_name, action, ip_str):
    """
    Provides a generic way to add or remove an IP address from
    either the 'whitelist' or 'manual_blocklist' BPF maps.
    """
    try:
        bpf_map = b.get_table(map_name)
        key = ip_to_key(ip_str)
        if action == "add":
            # Add the IP to the map. The value (1) is arbitrary.
            bpf_map[key] = ctypes.c_uint32(1)
            print(f"[+] {ip_str} added to {map_name}.")
        elif action == "remove":
            # Delete the key from the map.
            del bpf_map[key]
            print(f"[-] {ip_str} removed from {map_name}.")
    except KeyError:
        print(f"[!] IP {ip_str} not found in {map_name}.")
    except Exception as e:
        print(f"[!] Error managing IP {ip_str}: {e}")

def list_ips(map_name):
    """
    Iterates over a BPF map and prints all IP addresses currently in it.
    """
    try:
        bpf_map = b.get_table(map_name)
        if not bpf_map.items():
            print(f"[*] {map_name} is empty.")
            return
        print(f"--- IPs in {map_name} ---")
        # Iterate over map keys and convert them back to IP strings.
        for key, _ in bpf_map.items():
            ip_addr = socket.inet_ntoa(struct.pack("I", key.saddr))
            print(f"  - {ip_addr}")
    except Exception as e:
        print(f"[!] Error listing IPs: {e}")

# --- Event Processing ---
def print_event(cpu, data, size):
    """
    This is the callback function for handling events sent from the BPF program.
    It's triggered when the BPF program flags an IP for excessive packets.
    """
    # The event data is cast to a C struct defined in the BPF program.
    event = b["events"].event(data)
    ip_addr = socket.inet_ntoa(struct.pack("I", event.saddr))
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - AUTO-BLOCKED - IP: {ip_addr}, Packets: {event.packet_count}\n"

    # Print to console, send alert, and write to log file.
    print(f"\n{log_entry.strip()}") # Use a newline to avoid overwriting the input prompt.
    send_telegram_alert(ip_addr, event.packet_count)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

# Open the ring buffer from the BPF program and set print_event as the callback.
b["events"].open_ring_buffer(print_event)

def bpf_event_loop():
    """
    A dedicated loop running in a background thread to continuously poll
    the BPF ring buffer for new events.
    """
    while True:
        try:
            b.ring_buffer_poll()
            time.sleep(0.5) # A short sleep to prevent busy-waiting.
        except KeyboardInterrupt:
            # Allows the thread to exit gracefully if the main program is interrupted.
            break

# --- Main Interactive Shell ---
def print_help():
    """Prints the list of available commands for the interactive shell."""
    print("\n--- Interactive DDoS Mitigation Controller ---")
    print("Commands:")
    print("  wl add <ip>         - Add an IP to the whitelist (e.g., wl add 8.8.8.8)")
    print("  wl remove <ip>      - Remove an IP from the whitelist")
    print("  wl list             - Show all IPs in the whitelist")
    print("  bl add <ip>         - Manually block an IP")
    print("  bl remove <ip>      - Manually unblock an IP")
    print("  bl list             - Show all manually blocked IPs")
    print("  help                - Show this help message")
    print("  exit                - Detach program and quit")
    print("------------------------------------------")

if __name__ == "__main__":
    # Start the BPF event polling in a separate, non-blocking thread.
    event_thread = threading.Thread(target=bpf_event_loop)
    event_thread.daemon = True # Ensures thread exits when the main program does.
    event_thread.start()

    print(f"[*] Watching for events on {IFACE}...")
    print_help()

    try:
        # Main loop for the interactive command prompt.
        while True:
            cmd_input = input("ddos-ctl> ").strip().lower().split()
            if not cmd_input:
                continue

            command = cmd_input[0]
            if command == "exit":
                break
            elif command == "help":
                print_help()
            elif command in ["wl", "bl"]: # Whitelist or Blocklist commands
                map_name = "whitelist" if command == "wl" else "manual_blocklist"
                if len(cmd_input) > 1:
                    action = cmd_input[1]
                    if action == "list":
                        list_ips(map_name)
                    elif action in ["add", "remove"] and len(cmd_input) > 2:
                        ip = cmd_input[2]
                        manage_ip_list(map_name, action, ip)
                    else:
                        print("[!] Invalid syntax. Use 'help' for examples.")
                else:
                    print("[!] Invalid syntax. Use 'help' for examples.")
            else:
                print(f"[!] Unknown command: {command}")

    except KeyboardInterrupt:
        print("\n[*] Exiting by user request.")
    finally:
        # --- Cleanup ---
        # This block ensures the XDP program is detached from the interface
        # when the script exits, which is crucial for restoring normal network behavior.
        print("[*] Detaching XDP program...")
        b.remove_xdp(IFACE, 0)
        print("[*] Program detached. Exiting.")
