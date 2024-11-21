from scapy.all import sniff, Ether, IP, TCP, UDP
import threading
import time
from collections import defaultdict

event_data = {
    "Ethernet": [],
    "TCP": [],
    "UDP": []
}
unique_ips = set()
unique_macs = set()
exit_flag = threading.Event()

def update_event_data(protocol, src_addr, message_size):
   event_data[protocol].append(message_size)
   if protocol == "Ethernet":
       unique_macs.add(src_addr)
   else:
       unique_ips.add(src_addr)
  
def log_event(protocol, src_addr, dest_addr, message_size):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    log_message = f"{timestamp} - {protocol} - Source: {src_addr}, Destination: {dest_addr}, Size: {message_size} bytes\n"
    with open("network_events.log", "a") as log_file:
        log_file.write(log_message)
    print(log_message)
    update_event_data(protocol, src_addr, message_size)


def process_packet(packet):
      if exit_flag.is_set():
          return False # Stop sniffing if exit flag is set

      # Ethernet layer
      if packet.haslayer(Ether):
          eth_src = packet[Ether].src
          eth_dst = packet[Ether].dst
          message_size = len(packet)
          log_event("Ethernet", eth_src, eth_dst, message_size)

      # IP layer and specific protocols (TCP/UDP)
      if packet.haslayer(IP):
          src_ip = packet[IP].src
          dest_ip = packet[IP].dst
          message_size = len(packet)

          if packet.haslayer(TCP):
              log_event("TCP", src_ip, dest_ip, message_size)
          elif packet.haslayer(UDP):
              log_event("UDP", src_ip, dest_ip, message_size)

def start_sniffing():
    print("Starting packet sniffing...")
    sniff(filter="ip or tcp or udp", prn=process_packet, store=0,stop_filter=lambda x: exit_flag.is_set())

sniff_thread = threading.Thread(target=start_sniffing) 
sniff_thread.start()

def calculate_statistics():
    print("\n--- Network Statistics ---")
    for protocol, sizes in event_data.items():
        total_connections = len(sizes)
        average_size = sum(sizes) / total_connections if total_connections  > 0 else 0
        print(f"{protocol} Connections: {total_connections}, Average Message Size: {average_size:.2f} bytes")

    print(f"Unique IP Addresses: {len(unique_ips)}")
    print(f"Unique MAC Addresses: {len(unique_macs)}")
    print("-------------------------\n")

try:
    while not exit_flag.is_set():
        time.sleep(30)
        calculate_statistics()
except KeyboardInterrupt:
        print("\nStopping Network Event Logger.")
        exit_flag.set() # Signal the sniffing thread to stop

finally:
        sniff_thread.join() # Ensure the sniffing thread terminates
        calculate_statistics() # Print final statistics
        print("Sniffing stopped.")