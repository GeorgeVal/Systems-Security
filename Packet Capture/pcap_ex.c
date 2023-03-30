#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <getopt.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <signal.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <math.h>

typedef struct packets{
	int total_packets;
	int tcp_packets;
	int udp_packets;
	long int tcp_bytes; 
	long int udp_bytes;
	int net_flows;
	int tcp_flows;
	int udp_flows;
	int retransmissions;
}packets;

//initializes packets structure
void init_packets_(packets packet_){
	packet_.total_packets=0;
	packet_.tcp_packets=0;
	packet_.udp_packets=0;
	packet_.tcp_bytes=0;
	packet_.udp_bytes=0;
	packet_.net_flows=0;
	packet_.tcp_flows=0;
	packet_.udp_flows=0;
	packet_.retransmissions=0;
	return;
}

//Node structure
typedef struct hashMap_node{
	char* data;
	struct hashMap_node *next;
}Node;

//prints node list
void printList(Node* head) {
	printf("Node List: \n");
	while (head != NULL) {
		printf("%s \n", head->data);
		head = head->next;
	}
	printf("\n");
	}

//creates new node
Node* createNode(char* data) {
  Node* newNode = (Node*) malloc(sizeof(Node));
  newNode->data = strdup(data);
  newNode->next = NULL;
  return newNode;
}

//checks if node already exists and if not, adds it to end of node list
int insert(Node** head, char* data) {
  
  Node* current = *head;
  while (current != NULL) {
    if (strcmp(current->data, data) == 0) {
      // Data is already present in the list, do not insert a new node
      return -1;
    }
    current = current->next;
  }
  // Create a new node
  Node* newNode = createNode(data);
  //printf("New Node: \n");
  //printList(newNode);

  // Special case for empty list
  if (*head == NULL) {
    *head = newNode;
    return 1;
  }

  // Traverse the list to find the last node
  current = *head;
  while (current->next != NULL) {
    current = current->next;
  }

  
// Insert the new node at the end of the list
current->next = newNode;
return 1;
   
}

//empties node list
void emptyList(Node* head) {
  Node* current = head;
  Node* next;
  while (current != NULL) {
    next = current->next;
    free(current);
    current = next;
  }
}


//global variables
packets packet_;
FILE* fp;
// Create an empty list
Node* head = NULL;

//called whenever ^C is pressed, to save statistics
void signal_handler(int signum)
{
	fprintf(fp, "  UDP packets: %d\n", packet_.udp_packets);
	fprintf(fp, "  TCP packets: %d\n", packet_.tcp_packets);
    fprintf(fp, "  Total packets: %d\n", packet_.total_packets);
	fprintf(fp, "  UDP_bytes: %ld\n", packet_.udp_bytes);
	fprintf(fp, "  TCP_bytes: %ld\n", packet_.tcp_bytes);
	packet_.net_flows = packet_.tcp_flows + packet_.udp_flows;
	fprintf(fp, "  UDP_Flows: %d\n", packet_.udp_flows);
	fprintf(fp, "  TCP_Flows: %d\n", packet_.tcp_flows);
	fprintf(fp, "  Total Network Flows: %d\n", packet_.net_flows);
	fprintf(fp, "  Retransmissions: %d\n", packet_.retransmissions);
	fclose(fp);
	emptyList(head);
    exit(EXIT_SUCCESS);
}

//decodes IPv4 packets received
void IPV4_decode(const unsigned char *packet, pcap_t *handle, int port){

	struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
	struct in_addr source_address, destination_address;
	source_address.s_addr = ip_header->ip_src.s_addr;
    destination_address.s_addr = ip_header->ip_dst.s_addr;
	char str[100];

	//if packet is not TCP or UDP then increase packet counter and read next packet
	if ((ip_header->ip_p != IPPROTO_UDP) && (ip_header->ip_p != IPPROTO_TCP)) {
		//printf("  NO TCP/UDP \n");
		packet_.total_packets++;
		return;
	}

	//if packet is UDP gather its information
	else if(ip_header->ip_p == IPPROTO_UDP){ 
		struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

		//if port is not set then read all udp packets, else decode udp packets with src or dst port equal to port
		if(port<0 || (port == ntohs(udp_header->uh_sport) || port == ntohs(udp_header->uh_dport))){
			fprintf(fp,"  Protocol: %u (UDP)\n", ip_header->ip_p);
			fprintf(fp,"  Source IP: %s\n", inet_ntoa(ip_header->ip_src));
			fprintf(fp,"  Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
			fprintf(fp,"  Source port: %u\n", ntohs(udp_header->uh_sport));
			fprintf(fp,"  Destination port: %u\n", ntohs(udp_header->uh_dport));
			fprintf(fp,"  Header length: %u\n", 8);  // UDP header is always 8 bytes
			fprintf(fp,"  Payload length: %u\n", ntohs(udp_header->uh_ulen) - 8);  // uh_ulen includes header and payload
			packet_.udp_packets++;
			packet_.udp_bytes += ntohs(udp_header->uh_ulen);
			
  			sprintf(str, "%u:%u:%u:%u:%u", IPPROTO_UDP, source_address.s_addr, ntohs(udp_header->uh_sport),  destination_address.s_addr, ntohs(udp_header->uh_dport));
			//printf("%s \n",str);

			//if packet is unique (has unique 5-tuple{source IP address, source port, destination IP address, destination port, protocol}), then it is inserted in node list, and udp_flow counter increases
			if(insert(&head,str)>0){
				packet_.udp_flows++;
			}
		}
		// else{
		// 	printf("Didnt pass filter\n");
		// }
	}
	else { 
		//if port is not set decode all TCP packets, else decode only the ones with src and dst port equal to port
		struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
		if(port<0 || port == ntohs(tcp_header->th_sport) || port == ntohs(tcp_header->th_dport)){
			fprintf(fp,"  Protocol: %u (TCP)\n", ip_header->ip_p);
			fprintf(fp,"  Source IP: %s\n", inet_ntoa(ip_header->ip_src));
			fprintf(fp,"  Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
			fprintf(fp,"  Source port: %u\n", ntohs(tcp_header->th_sport));
			fprintf(fp,"  Destination port: %u\n", ntohs(tcp_header->th_dport));
			// The th_off field of this structure represents the length of the TCP header in 32-bit words.
			// The line of code multiplies the value of th_off by 4 to convert the length from 32-bit words to bytes. 
			// This is because each 32-bit word is 4 bytes long.
			// For example, if th_off is 5, the TCP header length will be 5 * 4 = 20 bytes.
			// This value is often used to skip over the TCP header and access the data payload of the packet.
			fprintf(fp,"  Header length: %u\n", tcp_header->th_off * 4);  // th_off is in 32-bit words
			fprintf(fp,"  Payload length: %lu\n", ntohs(ip_header->ip_len) - sizeof(struct ip) - tcp_header->th_off * 4);  // ip_len includes header and payload


			packet_.tcp_packets++;
			packet_.tcp_bytes += ntohs(ip_header->ip_len) - sizeof(struct ip);
		
			//if TH_RST flag is set then packet is a retransmission
			if (tcp_header->th_flags & TH_RST) {
				fprintf(fp, "  Retransmitted\n");
				packet_.retransmissions++;
				}
			//write packet info to str
			sprintf(str, "%u:%u:%u:%u:%u", IPPROTO_TCP, source_address.s_addr, ntohs(tcp_header->th_sport), destination_address.s_addr, ntohs(tcp_header->th_dport));
			
			//if packet is unique (has unique 5-tuple{source IP address, source port, destination IP address, destination port, protocol}), then it is inserted in node list, and tcp_flow counter increases
			if(insert(&head,str)>0){
				packet_.tcp_flows++;
			}


		}
		// else{
		// 	printf("Didnt pass filter\n");
		// }
	}
	packet_.total_packets++;
	return;

}

//Used to decode IPv4 packets read from a .pcap file
void IPV4_decode_offline(const unsigned char *packet, pcap_t *handle){

	struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
	struct in_addr source_address, destination_address;
	source_address.s_addr = ip_header->ip_src.s_addr;
    destination_address.s_addr = ip_header->ip_dst.s_addr;
	char str[100];


	if ((ip_header->ip_p != IPPROTO_UDP) && (ip_header->ip_p != IPPROTO_TCP)) {
		//printf("  NO TCP/UDP \n");
		packet_.total_packets++;
		return;
	}

	//packet protocol is UDP
	else if(ip_header->ip_p == IPPROTO_UDP){ 
		struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
		printf("  Protocol: %u (UDP)\n", ip_header->ip_p);
		printf("  Source IP: %s\n", inet_ntoa(ip_header->ip_src));
		printf("  Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
		printf("  Source port: %u\n", ntohs(udp_header->uh_sport));
		printf("  Destination port: %u\n", ntohs(udp_header->uh_dport));
		printf("  Header length: %u\n", 8);  // UDP header is always 8 bytes
		printf("  Payload length: %u\n", ntohs(udp_header->uh_ulen) - 8);  // uh_ulen includes header and payload
		packet_.udp_packets++;

		//udp bytes are equal to payload + header length
		packet_.udp_bytes += ntohs(udp_header->uh_ulen);
		
		sprintf(str, "%u:%u:%u:%u:%u", IPPROTO_UDP, source_address.s_addr, ntohs(udp_header->uh_sport),  destination_address.s_addr, ntohs(udp_header->uh_dport));
		//printf("%s \n",str);

		//if packet is unique (has unique 5-tuple{source IP address, source port, destination IP address, destination port, protocol}), then it is inserted in node list, and udp_flow counter increases
		if(insert(&head,str)>0){
			packet_.udp_flows++;
		}
		
	}
	else { 
		struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
		printf("  Protocol: %u (TCP)\n", ip_header->ip_p);
		printf("  Source IP: %s\n", inet_ntoa(ip_header->ip_src));
		printf("  Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
		printf("  Source port: %u\n", ntohs(tcp_header->th_sport));
		printf("  Destination port: %u\n", ntohs(tcp_header->th_dport));
		// The th_off field of this structure represents the length of the TCP header in 32-bit words.
		// The line of code multiplies the value of th_off by 4 to convert the length from 32-bit words to bytes. 
		// This is because each 32-bit word is 4 bytes long.
		// For example, if th_off is 5, the TCP header length will be 5 * 4 = 20 bytes.
		// This value is often used to skip over the TCP header and access the data payload of the packet.
		printf("  Header length: %u\n", tcp_header->th_off * 4);  // th_off is in 32-bit words
		printf("  Payload length: %lu\n", ntohs(ip_header->ip_len) - sizeof(struct ip) - tcp_header->th_off * 4);  // ip_len includes header and payload
		//fprintf(fp,"  Total length: %d\n", header.len);  // uh_ulen includes header and payload
		packet_.tcp_packets++;

		//tcp bytes are equal to payload + header length
		packet_.tcp_bytes += ntohs(ip_header->ip_len) - sizeof(struct ip);
	
		//if TH_RST flag is set then packet is a retransmission
		if (tcp_header->th_flags & TH_RST) {
			packet_.retransmissions++;
			printf("  Retransmitted\n");
			}
		//write packet info to str
		sprintf(str, "%u:%u:%u:%u:%u", IPPROTO_TCP, source_address.s_addr, ntohs(tcp_header->th_sport), destination_address.s_addr, ntohs(tcp_header->th_dport));

		//if packet is unique (has unique 5-tuple{source IP address, source port, destination IP address, destination port, protocol}), then it is inserted in node list, and tcp_flow counter increases
		if(insert(&head,str)>0){
			packet_.tcp_flows++;
		}
	}
	packet_.total_packets++;
	return;
}



//IPV6 packet decode function 
void IPV6_decode(const unsigned char *packet, pcap_t *handle, int port){

	struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
	char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
	u_char protocol;
	char str[100];

	//store IPv6 format src and dst ip's to src_ip and dst_ip
    inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip, INET6_ADDRSTRLEN);

	

	protocol = ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;

	//if protocol is not UDP or TCP then increase packet counter and return
	if ((protocol != IPPROTO_UDP) && (protocol != IPPROTO_TCP)) {
		//printf("  NO TCP/UDP \n");
		packet_.total_packets++;
	return;
	}
	else if(protocol == IPPROTO_UDP){ 
		struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
		if(port<0 || (port == ntohs(udp_header->uh_sport) || port == ntohs(udp_header->uh_dport))){
			fprintf(fp,"  Protocol: %u (UDP)\n", protocol);
			fprintf(fp,"  Source IP: %s\n", src_ip);
    		fprintf(fp,"  Destination IP: %s\n", dst_ip);
			fprintf(fp,"  Source port: %u\n", ntohs(udp_header->uh_sport));
			fprintf(fp,"  Destination port: %u\n", ntohs(udp_header->uh_dport));
			fprintf(fp,"  Header length: %u\n", 8);  // UDP header is always 8 bytes
			fprintf(fp,"  Payload length: %u\n", ntohs(udp_header->uh_ulen) - 8);  // uh_ulen includes header and payload
			packet_.udp_packets++;
			//udp bytes are equal to uh->ulen = payload + header
			packet_.udp_bytes += ntohs(udp_header->uh_ulen);
			
			
  			sprintf(str, "%u:%s:%u:%s:%u", IPPROTO_UDP, src_ip, ntohs(udp_header->uh_sport),  dst_ip, ntohs(udp_header->uh_dport));
			
			//if 5-tuple is unique (referenced above) then add node to list and increase udp_flows counter
			if(insert(&head,str)>0){
				packet_.udp_flows++;
			}
		
		}
		// else{
		// 	printf("Didnt pass filter\n");
		// }
	}
	else { 
		struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
		if(port<0 || port == ntohs(tcp_header->th_sport) || port == ntohs(tcp_header->th_dport)){
			fprintf(fp,"  Protocol: %u (TCP)\n", protocol);
			fprintf(fp,"  Source IP: %s\n", src_ip);
    		fprintf(fp,"  Destination IP: %s\n", dst_ip);
			fprintf(fp,"  Source port: %u\n", ntohs(tcp_header->th_sport));
			fprintf(fp,"  Destination port: %u\n", ntohs(tcp_header->th_dport));
			// The th_off field of this structure represents the length of the TCP header in 32-bit words.
			// The line of code multiplies the value of th_off by 4 to convert the length from 32-bit words to bytes. 
			// This is because each 32-bit word is 4 bytes long.
			// For example, if th_off is 5, the TCP header length will be 5 * 4 = 20 bytes.
			// This value is often used to skip over the TCP header and access the data payload of the packet.
			fprintf(fp,"  Header length: %u\n", tcp_header->th_off * 4);  // th_off is in 32-bit words
			fprintf(fp,"  Payload length: %u\n", ntohs(ip6_header->ip6_plen) - tcp_header->th_off * 4);  // ip_plen includes header and payload
			packet_.tcp_packets++;
			packet_.tcp_bytes += ntohs(ip6_header->ip6_plen) ;

			//if TH_RST flag is set then packet is a retransmission
			if (tcp_header->th_flags & TH_RST) {
				packet_.retransmissions++;
				fprintf(fp,"  Retransmitted\n");
				}
			sprintf(str, "%u:%s:%u:%s:%u", IPPROTO_TCP, src_ip, ntohs(tcp_header->th_sport), dst_ip, ntohs(tcp_header->th_dport));

			//if 5-tuple is unique (referenced above) then add node to list and increase tcp_flows counter
			if(insert(&head,str)>0){
				packet_.tcp_flows++;
			}

		}
		// else{
		// 	printf("Didnt pass filter\n");
		// }
	}
	packet_.total_packets++;
	return;
}

//IPv6 packet decode received from file
void IPV6_decode_offline(const unsigned char *packet, pcap_t *handle){

	struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
	char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
	u_char protocol;
	char str[100];

	//Gets source and destination ip and stores it to src_ip , dst_ip in IPv6 format
    inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip, INET6_ADDRSTRLEN);

	

	protocol = ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;

	if ((protocol != IPPROTO_UDP) && (protocol != IPPROTO_TCP)) {
	//	printf("  NO TCP/UDP \n");
		packet_.total_packets++;
	return;
	}
	else if(protocol == IPPROTO_UDP){ 
		struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
		printf("  Protocol: %u (UDP)\n", protocol);
		printf("  Source IP: %s\n", src_ip);
		printf("  Destination IP: %s\n", dst_ip);
		printf("  Source port: %u\n", ntohs(udp_header->uh_sport));
		printf("  Destination port: %u\n", ntohs(udp_header->uh_dport));
		printf("  Header length: %u\n", 8);  // UDP header is always 8 bytes
		printf("  Payload length: %u\n", ntohs(udp_header->uh_ulen) - 8);  // uh_ulen includes header and payload
		packet_.udp_packets++;

		//udp bytes are payload + header bytes
		packet_.udp_bytes += ntohs(udp_header->uh_ulen);
			
		sprintf(str, "%u:%s:%u:%s:%u", IPPROTO_UDP, src_ip, ntohs(udp_header->uh_sport),  dst_ip, ntohs(udp_header->uh_dport));

		//if 5-tuple is unique (referenced above) then store node to node list and increase udp_flows counter
		if(insert(&head,str)>0){
			packet_.udp_flows++;
		}
		
	}
	else { 
		struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
		printf("  Protocol: %u (TCP)\n", protocol);
		printf("  Source IP: %s\n", src_ip);
		printf("  Destination IP: %s\n", dst_ip);
		printf("  Source port: %u\n", ntohs(tcp_header->th_sport));
		printf("  Destination port: %u\n", ntohs(tcp_header->th_dport));

		// The th_off field of this structure represents the length of the TCP header in 32-bit words.
		// The line of code multiplies the value of th_off by 4 to convert the length from 32-bit words to bytes. 
		// This is because each 32-bit word is 4 bytes long.
		// For example, if th_off is 5, the TCP header length will be 5 * 4 = 20 bytes.
		// This value is used to skip over the TCP header and access the data payload of the packet.
		printf("  Header length: %u\n", tcp_header->th_off * 4);  // th_off is in 32-bit words
		printf("  Payload length: %u\n", ntohs(ip6_header->ip6_plen) - tcp_header->th_off * 4);  // ip_plen includes header and payload

		packet_.tcp_packets++;
		packet_.tcp_bytes += ntohs(ip6_header->ip6_plen) ;
		//if TH_RST flag is set then packet is a retransmission
		if (tcp_header->th_flags & TH_RST) {
			packet_.retransmissions++;
			printf("  Retransmitted\n");
			}
		sprintf(str, "%u:%s:%u:%s:%u", IPPROTO_TCP, src_ip, ntohs(tcp_header->th_sport), dst_ip, ntohs(tcp_header->th_dport));
		
		//if 5-tuple is unique (referenced above) then store node to node list and increase tcp_flows counter
		if(insert(&head,str)>0){
			packet_.tcp_flows++;
		}

	}
	packet_.total_packets++;
	return;
}

//reads and decode packets read from .pcap files
int packet_file_capture(char* pcap_name){
	
	char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
	pcap_t *handle;
	const unsigned char *packet;
    struct pcap_pkthdr *header;
	init_packets_(packet_);

	//signal handler for saving in file certain statistics (eg. network flows) when ^C
	signal(SIGINT, signal_handler);

	handle = pcap_open_offline(pcap_name, error_buffer);
	if (handle == NULL) {
        printf("Could not open file %s: %s\n", pcap_name, error_buffer);
        exit(-1);
    }

	
	while (pcap_next_ex(handle, &header, &packet) >= 0) {
	
		struct ether_header *eth_header = (struct ether_header *)packet;
		if (packet == NULL) {
			printf("  Packet = NULL\n");
			continue;
		}

		//if you have IPv4 packet then decode with appropriate function
		if ((ntohs(eth_header->ether_type) == ETHERTYPE_IP)){
	
			IPV4_decode_offline(packet, handle);
		}
		//else if you have IPv6 packet then decode with appropriate function	
		else if ((ntohs(eth_header->ether_type) == ETHERTYPE_IPV6)){
			
			IPV6_decode_offline(packet, handle);
		}
		else{
				printf("  Not IPV4 or IPV6 packet\n");
				packet_.total_packets++;
				continue;
		}

		//prints list of all unique packets stored in a node list
		//printList(head);

	
  	}
	printf("  UDP packets: %d\n", packet_.udp_packets);
	printf("  TCP packets: %d\n", packet_.tcp_packets);
	printf("  Total packets: %d\n", packet_.total_packets);
	printf("  UDP_bytes: %ld\n", packet_.udp_bytes);
	printf("  TCP_bytes: %ld\n", packet_.tcp_bytes);
	packet_.net_flows = packet_.tcp_flows + packet_.udp_flows;
	printf("  UDP_Flows: %d\n", packet_.udp_flows);
	printf("  TCP_Flows: %d\n", packet_.tcp_flows);
	printf("  Total Network Flows: %d\n", packet_.net_flows);
	printf("  Retransmissions: %d\n", packet_.retransmissions);
	
		
	//printList(head);
	emptyList(head);	

  	/* Close the handle and exit */
  	pcap_close(handle);
  	return 0;

}

//read and decode packets captured from a network interface specified by user
int packet_capture(char* net_if, char *filter){
    
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
	pcap_t *handle;
	const unsigned char *packet;
    struct pcap_pkthdr *header;
	int port =0;
	FILE* pcap_file;
	
	init_packets_(packet_);
	
	
    //signal handler for saving in file certain statistics (e.g. network flows) when ^C
	signal(SIGINT, signal_handler);

	
	//BUFSIZ is maximum packet size and 1000 is maximum time to wait before packet read
	handle = pcap_open_live(net_if, BUFSIZ, 1, 1000, error_buffer);
	
	
	if (handle == NULL) {
		fprintf(stderr, "  Couldn't open device  %s: %s\n", net_if, error_buffer);
		return -1;
	}

	if(filter!=NULL){
		port = atoi(filter);
	}
	else{
		port=-1;
	}
	
	//open log file to update it with new packets
	fp = fopen("log.txt", "a+");
	while (pcap_next_ex(handle, &header, &packet) >= 0) {
	
		struct ether_header *eth_header = (struct ether_header *)packet;
		if (packet == NULL) {
			printf("  Packet = NULL\n");
			continue;
		}

		if ((ntohs(eth_header->ether_type) == ETHERTYPE_IP)){
	
			//decode received IPv4 packet 
			IPV4_decode(packet, handle, port);
		}
			
		else if ((ntohs(eth_header->ether_type) == ETHERTYPE_IPV6)){
			printf("IPV6 \n");
			//decode received IPv6 packet
			IPV6_decode(packet, handle, port);
		}
		else{
				printf("Not IPV4 or IPV6 packet\n");
				packet_.total_packets++;
				continue;
		}
	
  	}
	//this runs if program terminates without ^C
	fprintf(fp, "  UDP packets: %d\n", packet_.udp_packets);
	fprintf(fp, "  TCP packets: %d\n", packet_.tcp_packets);
	fprintf(fp, "  Total packets: %d\n", packet_.total_packets);
	fprintf(fp, "  UDP_bytes: %ld\n", packet_.udp_bytes);
	fprintf(fp, "  TCP_bytes: %ld\n", packet_.tcp_bytes);
	packet_.net_flows = packet_.tcp_flows + packet_.udp_flows;
	fprintf(fp, "  UDP_Flows: %d\n", packet_.udp_flows);
	fprintf(fp, "  TCP_Flows: %d\n", packet_.tcp_flows);
	fprintf(fp, "  Total Network Flows: %d\n", packet_.net_flows);
	fprintf(fp, "  Retransmissions: %d\n", packet_.retransmissions);

	//prints list of all unique packets stored in a node list	
	//printList(head);
	emptyList(head);
	fclose(fp);
  	

  	// Close the handle and exit 
  	pcap_close(handle);
  	return 0;
  }
  
//checks if user has root privileges
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

//prints help message
void usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
		   "Options:\n"
		   "-i Network interface name (e.g., eth0)\n"
		   "-r Packet capture file name (e.g., test.pcap) "
		   "-f Filter expression (e.g., port 8080)\n"
		   "-h, Help message\n\n"
		   );

	exit(0);
}

int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;
    char* net_if, *filter, *pcap_name;

	if (argc < 2)
		usage();

	
	if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!\n");
        exit(-1);
    }

	while ((ch = getopt(argc, argv, "hi:f:r:")) != -1) {
		switch (ch) {		
		case 'i':
            net_if = optarg;
			
			//if argc <=3 then no filter is applied, call packet_capture with NULL as filter
            if(argc <= 3){
				//printf("Net is: %s, Optarg is: %s\n",net_if, optarg);
				if(net_if == NULL){
					printf("Null network interface, exiting..\n");
					exit(-1);
				}
                packet_capture(net_if, NULL);
				exit(0);
            }
			
			break;
        case 'f':

			if(argc<=3){
				printf("Invalid format\n");
				usage();
				
			}
			//if argc > 3 then call packet_capture from here and use user specified filter
			else{
				filter = optarg;
				if(net_if == NULL){
					printf("Null network interface, exiting..\n");
					exit(-1);
				}
				if(filter==NULL){
					printf("No filter\n");
					exit(-1);
				}
				printf("Filter Aquired\n");
				packet_capture(net_if, filter);
				exit(0);
			}
			break;
		//if format is ok, then call function to read packets from file specified by user
		 case 'r':

		 	if(argc>3){
				printf("Too many arguments\n");
				usage();
			}
			pcap_name = optarg;
			packet_file_capture(pcap_name);
			break;
		
		default:
			usage();
		}

	}
}  