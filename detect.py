import os
import time
import argparse

parser = argparse.ArgumentParser(description='DDoS detector and network traffic capture script')
parser.add_argument('-i', '--interface', type=str, help='The name of the network interface to monitor', required=False)
parser.add_argument('-p', '--packet_threshold', type=int, help='The threshold for packets per second', required=False, default=10000)
parser.add_argument('-d', '--dumpdir', type=str, help='The directory to save the network traffic capture', required=False, default='/tmp/')
args = parser.parse_args()

if args.interface:
    interface = args.interface
else:
    with open("/proc/net/dev") as f:
        content = f.read()
    interfaces = [line.split(":")[0].strip() for line in content.splitlines()[2:]]

    interface = None
    for i in interfaces:
        if i != "lo":
            interface = i
            break

packet_threshold = args.packet_threshold
dumpdir = args.dumpdir

while True:
    with open("/proc/net/dev") as f:
        content = f.read()
    pkt_old = int(content.split(f"{interface}:")[1].split(" ")[2])
    time.sleep(1)
    with open("/proc/net/dev") as f:
        content = f.read()
    pkt_new = int(content.split(f"{interface}:")[1].split(" ")[2])
    
    pkt = pkt_new - pkt_old
    print(f"\r{pkt} packets/s on interface {interface}", end="\033[0K")
    
    if pkt > packet_threshold:
        print(f"\nDDoS detected: Exceeded {packet_threshold} packets per second on interface {interface}!")
        os.system(f"tcpdump -n -s0 -c 5000 -w {dumpdir}dump.{time.strftime('%Y%m%d-%H%M%S')}.cap")
        print(f"Network traffic captured at {time.ctime()} and saved to {dumpdir}dump.{time.strftime('%Y%m%d-%H%M%S')}.cap\n")
