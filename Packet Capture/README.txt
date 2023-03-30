Georgios Valavanis AM: 2019030065

This is an implementation that reads packets from a user specified network interface or a user specified .pcap file. It reads packets in a loop checking whether a packet is IPv4 or IPv6 or none
of them and calls the appropriate function to decode IPv4 or IPv6 packets. Then it checks if current packet is TCP or UDP and then proceeds to the extraction of information of the packet such
as source and destination's IPs , source and destination's ports , header and payload length.
Finally it stores the above data with certain statistics such as number of packets read and network
flows in a "log.txt" file or prints them in terminal (depends on whether it reads packets from network or from a file.

User can determine a filter that makes the program decode packets only if their source or destination ports match with filter.

Acceptable filter format is only the port number, 
e.g sudo ./pcap_ex -i enp0s3 -f 443
Filter is equal to 443 in the above example.

When reading from a network interface you can terminate the program with ^C.
A custom signal handler will be prompted and the required statistics will be saved before
exit.

A log.txt file will be updated every time you start the packet read.

When reading packets from a file instead of saving to the log.txt file all information
is printed to the terminal.

Every retransmitted packet has a Retransmitted written as it's last field.

There is an extra statistic counting retransmissions and saving them

Can you tell if an incoming TCP packet is a retransmission? If yes, how? If not, why?

Answer: Yes by checking if the TH_RST flag is set.

Checking whether a TCP packet is retransmitted by using the TH_RST flag is not a foolproof solution.

The TH_RST flag is used to indicate that the sender of the packet is requesting the receiver to reset the connection. This can happen when a packet is retransmitted, as well as in other situations, such as when the sender wants to terminate the connection. So it isn't 100% accurate.

Can you tell if an incoming UDP packet is a retransmission? If yes, how? If not, why?

Answer: No, udp packets dont have seq numbers or ack so checking if they are retransmissions
is not possible. 

UDP is a connectionless protocol that does not provide any guarantee of delivery, and it does not have any built-in mechanism for retransmitting lost packets.

There is a hashMap_node structure used to store packet info, to check whether a packet's 
combination of source IP address, source port, destination IP address, destination
port, protocol are unique.

There is a packets structure used to store packet's statistics.

To run .pcap file put it in this folder or type absolute path in terminal.
