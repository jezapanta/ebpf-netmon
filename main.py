# Import necessary libraries
from bcc import BPF
from time import sleep
from pathlib import Path
import signal
import ctypes
import socket
import struct
from datetime import datetime
import psutil 
import time

boot_time = psutil.boot_time()

class DataStruct(ctypes.Structure):
    _fields_ = [
        ("timestamp", ctypes.c_uint64),
        ("payload", ctypes.c_ubyte * 66)
    ]

def setpcap():
    # Prepare pcap format
    pcap_global_header = struct.pack(
        "IHHiIII",
        0xa1b2c3d4,  # Magic number
        2, 4,        # Version major, minor
        0, 0,        # Time zone, accuracy
        65535,       # Max packet size
        1            # Link-layer header type (Ethernet)
    )
    
    with open("outputebpf.pcap", "wb") as file:
        file.write(pcap_global_header)

def print_debug_event(cpu, data, size):

    event = ctypes.cast(data, ctypes.POINTER(DataStruct)).contents

    timestamp = struct.pack("<Q", event.timestamp)
    actual_time_sec = boot_time + (event.timestamp / 1e9)
    print(actual_time_sec)
    human_time = datetime.fromtimestamp(actual_time_sec)

    # Demo purpose only
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload = ' '.join(f'{x:02x}' for x in event.payload[0:])

    #if (src_ip == "192.168.1.15" or dest_ip == "192.168.1.15") and render_proto == "TCP" :

    print(f"{time} Packet: {payload}")
    

    # PCAP Packet Header (16 bytes) - Example timestamp
    ts_sec = int(actual_time_sec)    # Example timestamp (Jan 1, 2022)
    ts_usec = int((actual_time_sec - ts_sec) * 1_000_000)
    packet_len = 66  # Packet size including Ethernet header (14 bytes) + IPv4 (20 bytes) + TCP (20 bytes)
    pcap_packet_header = struct.pack("IIII", ts_sec, ts_usec, packet_len, packet_len)


    with open("outputebpf.pcap", "ab") as file:
        file.write(pcap_packet_header)
        file.write(bytes(event.payload))
    #logger.debug(f"Packet: {src_ip}:{src_port} -> {dest_ip}:{dest_port} on {render_proto} -- [{payload_length}] {data}")

bpf_source = Path('probes/dump.c').read_text()
bpf = BPF(text=bpf_source)
xdp_fn = bpf.load_func("test", BPF.XDP)
bpf.attach_xdp("ens160", xdp_fn, 0)
# bpf.remove_xdp("ens160", 0)

setpcap()
# exit()

# Access the packet_count_map defined in the eBPF program
#packet_count_map = bpf.get_table("packet_count_map")

bpf["debug_events"].open_perf_buffer(print_debug_event)

# Poll for new events
try:
    while True:
        bpf.perf_buffer_poll()
except KeyboardInterrupt:
    print("Detaching eBPF program...")
    bpf.remove_xdp("ens160", 0)