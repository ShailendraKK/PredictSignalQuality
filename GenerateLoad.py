from scapy.all import *
from random import randint
import time
from threading import *

# Generate packet
#pkts = Ether()/IP(src="10.0.0.1",dst="10.0.0.2")/TCP(dport=53,flags='S')/Raw(RandString(size=120))

pkt =  Ether(src='00:00:00:00:00:01', dst='ff:ff:ff:ff:ff:ff')

pktList = []
start_time=time.time()

pkts = pkt /IP(dst="10.0.0.2") / TCP(dport=1234, sport=4321) / Raw(RandString(size=100))
for pktNum in range(0,10000):
    wrpcap('load.pcap', pkts, append=True)

pkts = pkt /IP(dst="10.0.0.2") / TCP(dport=1234, sport=4321) / Raw(RandString(size=1200))
for pktNum in range(0,10000):
    wrpcap('load.pcap', pkts, append=True)
pkts = pkt /IP(dst="10.0.0.2") / TCP(dport=1234, sport=4321) / Raw(RandString(size=1300))
for pktNum in range(0,10000):
    wrpcap('load.pcap', pkts, append=True)

pkts = pkt /IP(dst="10.0.0.2") / TCP(dport=1234, sport=4321) / Raw(RandString(size=1400))
for pktNum in range(0,10000):
    wrpcap('load.pcap', pkts, append=True)

pkts = pkt /IP(dst="10.0.0.2") / TCP(dport=1234, sport=4321) / Raw(RandString(size=200))
for pktNum in range(0,10000):
    wrpcap('load.pcap', pkts, append=True)

pkts = pkt /IP(dst="10.0.0.2") / TCP(dport=1234, sport=4321) / Raw(RandString(size=300))
for pktNum in range(0,10000):
    wrpcap('load.pcap', pkts, append=True)

pkts = pkt /IP(dst="10.0.0.2") / TCP(dport=1234, sport=4321) / Raw(RandString(size=400))
for pktNum in range(0,10000):
    wrpcap('load.pcap', pkts, append=True)

pkts = pkt /IP(dst="10.0.0.2") / TCP(dport=1234, sport=4321) / Raw(RandString(size=500))
for pktNum in range(0,10000):
    wrpcap('load.pcap', pkts, append=True)

pkts = pkt /IP(dst="10.0.0.2") / TCP(dport=1234, sport=4321) / Raw(RandString(size=600))
for pktNum in range(0,10000):
    wrpcap('load.pcap', pkts, append=True)

pkts = pkt /IP(dst="10.0.0.2") / TCP(dport=1234, sport=4321) / Raw(RandString(size=700))
for pktNum in range(0,10000):
    wrpcap('load.pcap', pkts, append=True)

pkts = pkt /IP(dst="10.0.0.2") / TCP(dport=1234, sport=4321) / Raw(RandString(size=800))
for pktNum in range(0,10000):
    wrpcap('load.pcap', pkts, append=True)

pkts = pkt /IP(dst="10.0.0.2") / TCP(dport=1234, sport=4321) / Raw(RandString(size=900))
for pktNum in range(0,10000):
    wrpcap('load.pcap', pkts, append=True)

pkts = pkt /IP(dst="10.0.0.2") / TCP(dport=1234, sport=4321) / Raw(RandString(size=1000))
for pktNum in range(0,10000):
    wrpcap('load.pcap', pkts, append=True)

pkts = pkt /IP(dst="10.0.0.2") / TCP(dport=1234, sport=4321) / Raw(RandString(size=1100))
for pktNum in range(0,10000):
    wrpcap('load.pcap', pkts, append=True)

# Send the list of packets

print time.time() - start_time,"seconds"
print 
#print start_time, "secs"