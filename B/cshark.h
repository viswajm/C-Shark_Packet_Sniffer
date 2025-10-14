#ifndef CSHARK_H
#define CSHARK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <pcap.h>
#include <pthread.h>
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

#define ETHER_TYPE_IPv4 0x0800
#define ETHER_TYPE_IPV6 0x86DD
#define ETHER_TYPE_ARP 0x0806

// LLM Generated Code Begins
//  Ethernet header (14 bytes)
struct eth_hdr
{
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype; // network order
} __attribute__((packed));

struct ipv4_hdr
{
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
} __attribute__((packed));

// IPv6 header (40 bytes)
struct ipv6_hdr
{
    uint32_t ver_tc_flow;
    uint16_t payload_len;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src[16];
    uint8_t dst[16];
} __attribute__((packed));

// ARP header (28 bytes)
struct arp_hdr
{
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
} __attribute__((packed));

// TCP header (variable length)
struct tcp_hdr
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t offset_reserved; // data offset = high 4 bits
    uint8_t flags;
    uint16_t win;
    uint16_t checksum;
    uint16_t urg_ptr;
} __attribute__((packed));

// UDP header (8 bytes)
struct udp_hdr
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
} __attribute__((packed));

// TCP Flag Definitions
#ifndef TH_FIN
#define TH_FIN 0x01
#endif
#ifndef TH_SYN
#define TH_SYN 0x02
#endif
#ifndef TH_RST
#define TH_RST 0x04
#endif
#ifndef TH_PUSH
#define TH_PUSH 0x08
#endif
#ifndef TH_ACK
#define TH_ACK 0x10
#endif
#ifndef TH_URG
#define TH_URG 0x20
#endif
#ifndef TH_ECE
#define TH_ECE 0x40
#endif
#ifndef TH_CWR
#define TH_CWR 0x80
#endif
#ifndef TH_NS
#define TH_NS 0x100
#endif

// LLM Generated Code Ends
void print_ethernet_layer(const unsigned char *packet);
void print_ipv4_layer(const unsigned char *packet, uint32_t caplen, uint32_t off);
void print_ipv6_layer(const unsigned char *packet, uint32_t caplen, uint32_t off);
void print_arp_layer(const unsigned char *packet, uint32_t caplen, uint32_t off);
void print_tcp_layer(const unsigned char *packet, uint32_t caplen, uint32_t off);
void print_udp_layer(const unsigned char *packet, uint32_t caplen, uint32_t off);
void packet_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet);
void print_payload(const unsigned char *payload, int payload_len);
void sniffer(const char *d);
void sigint_handler(int signo);

#endif