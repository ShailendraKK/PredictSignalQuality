sudo tcpreplay -i vf0_0 --mbps=100 load.pcap
#sudo ip netns exec ns_server tcpreplay -i vf0_0 -L 15 16-10-12.pcap