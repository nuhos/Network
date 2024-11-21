from scapy.all import sniff, Ether, IP, TCP, UDP
import threading
import time
from collections import defaultdict

# Shared Data
event_data = {"Ethernet": [], "TCP": [], "UDP": []}
throughput_data = defaultdict(int)
latency_data = {}
unique_ips = set()
unique_macs = set()
exit_flag = threading.Event()

# Update and Log Functions
def update_event_data(protocol, src_addr, dest_addr, message_size, timestamp):
    event_data[protocol].append(message_size)
    throughput_data[protocol] += message_size
    if protocol == "Ethernet":
        unique_macs.add(src_addr)
    else:
        unique_ips.add(src_addr)

    if protocol in ["TCP", "UDP"]:
        conn_key = (src_addr, dest_addr)
        if conn_key not in latency_data:
            latency_data[conn_key] = {"start": timestamp}
        else:
            latency_data[conn_key]["end"] = timestamp

def log_event(protocol, src_addr, dest_addr, message_size):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    log_message = f"{timestamp} - {protocol} - Source: {src_addr}, Destination: {dest_addr}, Size: {message_size} bytes\n"
    with open("network_events.log", "a") as log_file:
        log_file.write(log_message)
    print(log_message)

# Process Packet
def process_packet(packet):
    if exit_flag.is_set():
        return False

    timestamp = time.time()
    if packet.haslayer(Ether):
        eth_src = packet[Ether].src
        eth_dst = packet[Ether].dst
        size = len(packet)
        log_event("Ethernet", eth_src, eth_dst, size)
        update_event_data("Ethernet", eth_src, eth_dst, size, timestamp)

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size = len(packet)
        if packet.haslayer(TCP):
            log_event("TCP", src_ip, dst_ip, size)
            update_event_data("TCP", src_ip, dst_ip, size, timestamp)
        elif packet.haslayer(UDP):
            log_event("UDP", src_ip, dst_ip, size)
            update_event_data("UDP", src_ip, dst_ip, size, timestamp)

# Throughput and Latency Calculations
def calculate_throughput(interval=10):
    print("\n--- Throughput (bps) ---")
    for protocol, bytes_count in throughput_data.items():
        bps = (bytes_count * 8) / interval
        print(f"{protocol}: {bps:.2f} bps")
        throughput_data[protocol] = 0

def calculate_latency():
    total_latency = 0
    count = 0
    for conn, times in latency_data.items():
        if "start" in times and "end" in times:
            total_latency += (times["end"] - times["start"]) * 1000
            count += 1
    avg_latency = total_latency / count if count > 0 else 0
    print(f"\nAverage Latency: {avg_latency:.2f} ms")

# Monitoring Functions
def calculate_statistics():
    print("\n--- Network Statistics ---")
    for protocol, sizes in event_data.items():
        total_connections = len(sizes)
        avg_size = sum(sizes) / total_connections if total_connections > 0 else 0
        print(f"{protocol} Connections: {total_connections}, Average Size: {avg_size:.2f} bytes")
    print(f"Unique IPs: {len(unique_ips)}, Unique MACs: {len(unique_macs)}")

def monitor_throughput_latency():
    while not exit_flag.is_set():
        time.sleep(10)
        calculate_throughput()
        calculate_latency()

# Start Threads
sniff_thread = threading.Thread(target=lambda: sniff(prn=process_packet, store=0, stop_filter=lambda _: exit_flag.is_set()))
monitor_thread = threading.Thread(target=monitor_throughput_latency)

sniff_thread.start()
monitor_thread.start()

# Main Loop
try:
    while not exit_flag.is_set():
        time.sleep(30)
        calculate_statistics()
except KeyboardInterrupt:
    exit_flag.set()

# Cleanup
finally:
    sniff_thread.join()
    monitor_thread.join()
    calculate_statistics()
    calculate_throughput()
    calculate_latency()
    print("Monitoring stopped.")
