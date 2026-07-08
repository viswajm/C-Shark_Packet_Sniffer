#ifndef CSHARK_H
#define CSHARK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>

// Use standard definitions from system headers
#define ETHER_TYPE_IPv4 ETHERTYPE_IP
#define ETHER_TYPE_IPV6 ETHERTYPE_IPV6
#define ETHER_TYPE_ARP ETHERTYPE_ARP

#define MAX_PACKETS 10000

typedef struct
{
    struct pcap_pkthdr header;
    const unsigned char *data;
    struct timeval timestamp;
    int length;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol; // TCP, UDP, ICMP, etc.
} packet_store;

// Use standard system headers for protocol structures
#define eth_hdr ether_header
#define ipv4_hdr iphdr
#define ipv6_hdr ip6_hdr
#define tcp_hdr tcphdr
#define udp_hdr udphdr
#define arp_hdr ether_arp

// TCP Flag Definitions (add any missing ones)
#ifndef TH_ECE
#define TH_ECE 0x40
#endif
#ifndef TH_CWR
#define TH_CWR 0x80
#endif
#ifndef TH_NS
#define TH_NS 0x100
#endif


// Live sniffing output functions
void print_ethernet_layer(const unsigned char *packet);
void print_ipv4_layer(const unsigned char *packet, uint32_t caplen, uint32_t off);
void print_ipv6_layer(const unsigned char *packet, uint32_t caplen, uint32_t off);
void print_arp_layer(const unsigned char *packet, uint32_t caplen, uint32_t off);
void print_tcp_layer(const unsigned char *packet, uint32_t caplen, uint32_t off);
void print_udp_layer(const unsigned char *packet, uint32_t caplen, uint32_t off);
void print_payload(const unsigned char *payload, int payload_len);
void packet_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet);

// Deep/inspection analysis functions
void deep_ethernet(const unsigned char *packet);
void deep_ipv4(const unsigned char *packet, uint32_t caplen, uint32_t off);
void deep_ipv6(const unsigned char *packet, uint32_t caplen, uint32_t off);
void deep_arp(const unsigned char *packet, uint32_t caplen, uint32_t off);
void deep_tcp(const unsigned char *packet, uint32_t caplen, uint32_t off);
void deep_udp(const unsigned char *packet, uint32_t caplen, uint32_t off);
void deep_payload(const unsigned char *payload, int len, const char *app_name);
void deep_hex_dump(const unsigned char *data, int len);

void inspect_packet(packet_store *sp);
void sniffer(const char *d);
void sniffer_with_filter(const char *d, const char *filter_exp);
void sigint_handler(int signo);
void free_captured_packets();

#endif