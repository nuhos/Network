import logging
import threading
import time
import datetime
from collections import defaultdict
from scapy.all import sniff, Ether, IP, TCP, UDP
import socket
import matplotlib.pyplot as plt
import numpy as np

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

plt.ion()

# Shared Data
event_data = {"Ethernet": [], "TCP": [], "UDP": []}
throughput_data = defaultdict(int)
latency_data = {}
unique_ips = set()
unique_macs = set()
protocol_packet_count = defaultdict(int)
connection_rate_data = defaultdict(list)
exit_flag = threading.Event()

SERVER_ADDRESS = '127.0.0.1'
server_port_number = 9999
tracked_connections = []
connection_rate_window = 30

# Thread-safe lock for shared resources
data_lock = threading.Lock()

# TCP server to handle multiple client connections
def handle_connections(client_socket):
    tracked_connections.append(client_socket)

def TCP_server_start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_ADDRESS, server_port_number))
    server.listen(5)
    logging.info(f"Server is listening on {SERVER_ADDRESS}:{server_port_number}")
    try:
        while not exit_flag.is_set():
            client_socket, addr = server.accept()
            client_thread = threading.Thread(target=handle_connections, args=(client_socket,))
            client_thread.start()
    except KeyboardInterrupt:
        exit_flag.set()
    finally:
        for conn in tracked_connections:
            conn.close()
        server.close()

# Logging function
def log_event(protocol, src_addr, dest_addr, message_size):
    timestamp = datetime.datetime.now()
    message = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {protocol} - Source: {src_addr}, Destination: {dest_addr}, Size: {message_size} bytes\n"
    with open("network_events.log", "a") as log_file:
        log_file.write(message)
    update_event_data(protocol, src_addr, dest_addr, message_size, timestamp)

# Update Event Data
def update_event_data(protocol, src_addr, dest_addr, message_size, timestamp):
    with data_lock:
        event_data[protocol].append(message_size)
        throughput_data[protocol] += message_size
        protocol_packet_count[protocol] += 1

        if protocol == "Ethernet":
            unique_macs.add(src_addr)
            connection_rate_data[protocol].append(timestamp)
        else:
            unique_ips.add(src_addr)

        if protocol in ["TCP", "UDP"]:
            conn_key = (src_addr, dest_addr)
            if conn_key not in latency_data:
                latency_data[conn_key] = {"start": timestamp}
            else:
                latency_data[conn_key]["end"] = timestamp

# Process Packet
def process_packet(packet):
    if exit_flag.is_set():
        return False

    timestamp = datetime.datetime.now()

    if packet.haslayer(Ether):
        eth_src = packet[Ether].src
        eth_dst = packet[Ether].dst
        size = len(packet)
        log_event("Ethernet", eth_src, eth_dst, size)

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size = len(packet)
        if packet.haslayer(TCP):
            log_event("TCP", src_ip, dst_ip, size)
        elif packet.haslayer(UDP):
            log_event("UDP", src_ip, dst_ip, size)

# Start sniffing
def sniffing_start():
    logging.info("Starting packet sniffing...")
    sniff(filter="ip or tcp or udp", prn=process_packet, store=0, stop_filter=lambda x: exit_flag.is_set())

# Throughput Calculation
def calculate_throughput(interval=10):
    with data_lock:
        logging.info("--- Throughput (bps) ---")
        for protocol, bytes_count in throughput_data.items():
            bps = (bytes_count * 8) / interval
            logging.info(f"{protocol}: {bps:.2f} bps")
            throughput_data[protocol] = 0

# Latency Calculation
def calculate_latency():
    total_latency = 0
    count = 0
    with data_lock:
        for conn, times in latency_data.items():
            if "start" in times and "end" in times:
                total_latency += (times["end"] - times["start"]).total_seconds() * 1000
                count += 1
    avg_latency = total_latency / count if count > 0 else 0
    logging.info(f"Average Latency: {avg_latency:.2f} ms")

# Display Statistics
def display_statistics():
    with data_lock:
        logging.info("Network Statistics:")
        for protocol, sizes in event_data.items():
            connections_number = len(sizes)
            avg_size = sum(sizes) / connections_number if connections_number > 0 else 0
            logging.info(f"{protocol} Connections: {connections_number}, Average Size: {avg_size:.2f} bytes")
        logging.info(f"Unique IP Addresses: {len(unique_ips)}")
        logging.info(f"Unique MAC Addresses: {len(unique_macs)}")

# Calculate Rate of New Connections
def calculate_connection_rate():
    current_time = datetime.datetime.now()
    with data_lock:
        for protocol, timestamps in connection_rate_data.items():
            recent_connections = [t for t in timestamps if (current_time - t).total_seconds() <= connection_rate_window]
            connection_rate_per_30_seconds = len(recent_connections)
            logging.info(f"Rate of new connections for {protocol} (last {connection_rate_window} seconds): {connection_rate_per_30_seconds} connections")


# Plot Graphs
def plot_graphs():
    try:
        fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(10, 15))

        # Throughput Over Time
        cumulative_throughput = defaultdict(list)
        timepoints = []  # Timepoints for plotting
        for protocol in event_data:
            if event_data[protocol]:  # Ensure there's data for the protocol
                cumulative_throughput[protocol] = np.cumsum(event_data[protocol])  # Calculate cumulative throughput

        max_data_length = max(len(cumulative_throughput[protocol]) for protocol in cumulative_throughput)
        timepoints = list(range(max_data_length))  # Use the maximum length among protocols as the x-axis

        for protocol, throughput_values in cumulative_throughput.items():
            # Adjust y-values to match the timepoints by padding with zeros if necessary
            throughput_values = list(throughput_values)
            while len(throughput_values) < max_data_length:
                throughput_values.append(0)
            ax1.plot(timepoints, throughput_values, label=protocol)

        ax1.set_title("Throughput Over Time")
        ax1.set_xlabel("Time (seconds)")
        ax1.set_ylabel("Cumulative Throughput (bytes)")
        ax1.legend()
        ax1.grid(True)

        # Latency Distribution
        latencies = []
        with data_lock:
            for conn, times in latency_data.items():
                if "start" in times and "end" in times:
                    latencies.append((times["end"] - times["start"]).total_seconds() * 1000)  # Convert to milliseconds
        if latencies:
            ax2.hist(latencies, bins=50, edgecolor="black")
        ax2.set_title("Latency Distribution")
        ax2.set_xlabel("Latency (ms)")
        ax2.set_ylabel("Frequency")
        ax2.grid(True)

        # Protocol Usage
        protocols = list(protocol_packet_count.keys())
        counts = list(protocol_packet_count.values())
        ax3.bar(protocols, counts)
        ax3.set_title("Protocol Usage Distribution")
        ax3.set_xlabel("Protocol")
        ax3.set_ylabel("Packet Count")
        ax3.grid(True)

        plt.tight_layout()
        plt.savefig("network_graphs.png")
        plt.close()
    except Exception as e:
        logging.error(f"Error generating visualizations: {e}")

# Data Collection Loop
def data_collection_loop():
    try:
        while not exit_flag.is_set():
            time.sleep(10)
            calculate_throughput()
            calculate_latency()
            if time.time() % 30 < 10:
                display_statistics()
                calculate_connection_rate()
    except KeyboardInterrupt:
        exit_flag.set()
    finally:
        display_statistics()
        plot_graphs()
        logging.info("Network monitoring terminated.")

# Main
if __name__ == "__main__":
    # Start threads
    server_thread = threading.Thread(target=TCP_server_start)
    sniff_thread = threading.Thread(target=sniffing_start)
    monitor_thread = threading.Thread(target=data_collection_loop)

    server_thread.start()
    sniff_thread.start()
    monitor_thread.start()

    try:
        while not exit_flag.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        exit_flag.set()

    server_thread.join()
    sniff_thread.join()
    monitor_thread.join()
    logging.info("Monitoring stopped.")