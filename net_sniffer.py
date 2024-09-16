import sys
import subprocess
import platform
import time
from scapy.all import sniff, IP, TCP, UDP
import threading
import signal

# Variables to keep track of packets and time
packet_count = 0
start_time = time.time()
stop_sniffing = threading.Event()

# Function to install missing packages
def install_package(package_name):
    try:
        print(f"Installing {package_name}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
        print(f"{package_name} installed successfully!")
    except subprocess.CalledProcessError as e:
        sys.exit(f"Failed to install {package_name}: {e}")

# Check and install scapy if not installed
try:
    from scapy.all import sniff, IP, TCP, UDP
except ImportError:
    install_package("scapy")
    from scapy.all import sniff, IP, TCP, UDP  # Re-import after installation

# Function to process packets with verbose output
def packet_handler(packet):
    global packet_count
    packet_count += 1
    
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_size = len(packet)
        
        if TCP in packet:
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            proto = "Other"
            src_port = None
            dst_port = None
        
        # Display detailed packet information
        print(f"\n[{proto}] Packet Size: {packet_size} bytes")
        print(f"Source IP: {ip_src} | Source Port: {src_port}")
        print(f"Destination IP: {ip_dst} | Destination Port: {dst_port}")
        print(f"Raw Packet: {bytes(packet).hex()[:64]}...")  # Show first 64 bytes of packet data for clarity

# Cross-platform interface selection
def get_default_iface():
    current_os = platform.system()

    if current_os == "Darwin":  # macOS
        return "en1"  # Default Wi-Fi interface on macOS
    elif current_os == "Linux":  # Linux
        return "wlan0"  # Default Wi-Fi interface on Linux (change as needed)
    elif current_os == "Windows":  # Windows
        from scapy.all import get_if_list
        return get_if_list()[0]  # Use the first available interface
    elif current_os == "Android":  # For termux or Python environments on Android
        return "wlan0"  # Default Wi-Fi interface on Android
    else:
        sys.exit(f"Unsupported OS: {current_os}")

# Signal handler for graceful exit
def signal_handler(sig, frame):
    global start_time, packet_count
    elapsed_time = time.time() - start_time
    print(f"\nProgram exit. Total packets captured: {packet_count}")
    print(f"Time taken: {elapsed_time:.2f} seconds")
    stop_sniffing.set()  # Signal to stop sniffing
    sys.exit(0)

# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)

# Thread function to handle packet sniffing
def sniff_packets(interface):
    print(f"Sniffing on interface: {interface}")
    sniff(iface=interface, filter="ip", prn=packet_handler, store=False, stop_filter=lambda x: stop_sniffing.is_set())

# Get the default interface for the platform
interface = get_default_iface()

# Start packet sniffing in a separate thread for better performance
sniffer_thread = threading.Thread(target=sniff_packets, args=(interface,))
sniffer_thread.start()

# Optionally, join the thread if you need to wait for its completion
sniffer_thread.join()