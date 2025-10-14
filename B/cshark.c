#include "cshark.h"

pcap_if_t *alldevices, *device;
char errbuf[PCAP_ERRBUF_SIZE];
static int packet_id = 1;
pcap_t *handle;

// LLM Generated Code Begins
volatile sig_atomic_t stop_sniffing = 0;

void sigint_handler(int sig)
{
    printf("\n[C-Shark] Caught Ctrl+C - packet sniffing stopped ...\n");
    stop_sniffing = 1;
    pcap_breakloop(handle);
}
// LLM Generated Code Ends

// ================= Layer Print Functions =================

void print_ethernet_layer(const unsigned char *packet)
{
    printf("L2 (Ethernet):\n");
    printf("Dst MAC Address: %02x:%02x:%02x:%02x:%02x:%02x | ", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    printf("Src MAC Address: %02x:%02x:%02x:%02x:%02x:%02x | \n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);

    unsigned short eth_type = (packet[12] << 8) | packet[13];
    printf("Ether Type: ");
    if (eth_type == ETHER_TYPE_IPv4)
    {
        printf("IPV4 (0x%04x)\n", eth_type);
    }
    else if (eth_type == ETHER_TYPE_IPV6)
    {
        printf("IPV6 (0x%04x)\n", eth_type);
    }
    else if (eth_type == ETHER_TYPE_ARP)
    {
        printf("ARP (0x%04x)\n", eth_type);
    }
    else
    {
        printf("Unknown (0x%04x)\n", eth_type);
    }

    printf("\n");
}

void print_ipv4_layer(const unsigned char *packet, uint32_t caplen, uint32_t off)
{
    printf("L3 (IPV4):\n");

    if (caplen < off + sizeof(struct ipv4_hdr))
    {
        printf("Truncated IPV4\n");
        return;
    }

    const struct ipv4_hdr *ip = (const struct ipv4_hdr *)(packet + off);
    uint8_t version = (ip->ver_ihl >> 4);
    uint8_t ihl = (ip->ver_ihl & 0x0F);
    uint16_t iphdr_length = ihl * 4;
    uint16_t frag_field = ntohs(ip->frag_off);
    uint8_t flags = (frag_field & 0xE000) >> 13;
    uint16_t frag_offset = frag_field & 0x1FFF;

    uint8_t df_flag = (flags & 0x2) >> 1;
    uint8_t mf_flag = (flags & 0x1);

    if (version != 4)
    {
        printf("Not IPv4 (ver=%u)\n", version);
        return;
    }

    if (caplen < off + iphdr_length)
    {
        printf("Truncated IPv4 header\n");
        return;
    }

    uint16_t ip_totlen = ntohs(ip->tot_len);
    char srcbuff[INET_ADDRSTRLEN], dstbuff[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->src, srcbuff, sizeof(srcbuff));
    inet_ntop(AF_INET, &ip->dst, dstbuff, sizeof(dstbuff));
    const char *proto;
    if (ip->protocol == IPPROTO_TCP)
    {
        proto = "TCP";
    }
    else if (ip->protocol == IPPROTO_UDP)
    {
        proto = "UDP";
    }
    else if (ip->protocol == IPPROTO_ICMP)
    {
        proto = "ICMP";
    }
    else
    {
        proto = "Unknown";
    }

    printf("Src IP: %s | Dst IP: %s | Protocol: %s (%u)\n", srcbuff, dstbuff, proto, ip->protocol);
    printf("Packet ID: 0x%04x | Header Length: %u bytes | Total Length: %u\n", ip->id, iphdr_length, ip_totlen);
    printf("Flags: [");
    if (df_flag)
    {
        printf("DF");
    }
    if (mf_flag)
    {
        printf("%sMF", df_flag ? ", " : "");
    }
    printf("] | Fragment Offset: %u | ", frag_offset);
    printf("TTL: %u\n", ip->ttl);
    printf("\n");
    int flag = 0;
    if (ip->protocol == IPPROTO_TCP)
    {
        flag = 1;
        print_tcp_layer(packet, caplen, off + iphdr_length);
    }
    else if (ip->protocol == IPPROTO_UDP)
    {
        flag = 1;
        print_udp_layer(packet, caplen, off + iphdr_length);
    }
    if (ip_totlen > iphdr_length && flag == 0)
    {
        print_payload(packet + off + iphdr_length, ip_totlen - iphdr_length);
    }
}

void print_ipv6_layer(const unsigned char *packet, uint32_t caplen, uint32_t off)
{
    printf("L3 (IPV6):\n");

    if (caplen < off + sizeof(struct ipv6_hdr))
    {
        printf("Truncated IPV6\n");
        return;
    }

    const struct ipv6_hdr *ip6 = (const struct ipv6_hdr *)(packet + off);
    uint8_t version = (ntohl(ip6->ver_tc_flow) >> 28);
    if (version != 6)
    {
        printf("Not IPv6 (ver=%u)\n", version);
        return;
    }

    char srcbuff[INET6_ADDRSTRLEN], dstbuff[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip6->src, srcbuff, sizeof(srcbuff));
    inet_ntop(AF_INET6, ip6->dst, dstbuff, sizeof(dstbuff));

    const char *proto;
    if (ip6->next_header == IPPROTO_TCP)
    {
        proto = "TCP";
    }
    else if (ip6->next_header == IPPROTO_UDP)
    {
        proto = "UDP";
    }
    else if (ip6->next_header == IPPROTO_ICMP)
    {
        proto = "ICMP";
    }
    else
    {
        proto = "Unknown";
    }

    printf("Src IP: %s | Dst IP: %s | Next Header: %s (%u)\n", srcbuff, dstbuff, proto, ip6->next_header);
    printf("Payload Length: %u bytes | Hop Limit: %u\n", ntohs(ip6->payload_len), ip6->hop_limit);

    uint8_t traffic_class = (ntohl(ip6->ver_tc_flow) & 0x0FF00000) >> 20;
    uint32_t flow_label = (ntohl(ip6->ver_tc_flow) & 0x000FFFFF);
    printf("Traffic Class: %u | Flow Label: 0x%05x\n", traffic_class, flow_label);
    printf("\n");
    int flag = 0;

    if (ip6->next_header == IPPROTO_TCP)
    {
        flag = 1;
        print_tcp_layer(packet, caplen, off + sizeof(struct ipv6_hdr));
    }
    else if (ip6->next_header == IPPROTO_UDP)
    {
        flag = 1;
        print_udp_layer(packet, caplen, off + sizeof(struct ipv6_hdr));
    }
    if (ip6->payload_len > 0 && flag == 0)
    {
        print_payload(packet + off + sizeof(struct ipv6_hdr), ntohs(ip6->payload_len));
    }
}

void print_arp_layer(const unsigned char *packet, uint32_t caplen, uint32_t off)
{
    printf("L3 (ARP):\n");

    if (caplen < off + sizeof(struct arp_hdr))
    {
        printf("Truncated ARP\n");
        return;
    }

    const struct arp_hdr *arp = (const struct arp_hdr *)(packet + off);
    printf("Operation: ");
    uint16_t oper = ntohs(arp->oper);

    if (oper == ARPOP_REQUEST)
        printf("Request (1)\n");
    else if (oper == ARPOP_REPLY)
        printf("Reply (2)\n");
    else
        printf("Unknown (%u)\n", oper);

    printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x | ",
           arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5]);
    printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5]);
    printf("Sender IP: %d.%d.%d.%d | ",
           arp->spa[0], arp->spa[1], arp->spa[2], arp->spa[3]);
    printf("Target IP: %d.%d.%d.%d\n",
           arp->tpa[0], arp->tpa[1], arp->tpa[2], arp->tpa[3]);
    printf("HW Type: %u | Protocol Type: 0x%04x | HW Length: %u | Protocol Length: %u\n",
           ntohs(arp->htype), ntohs(arp->ptype), arp->hlen, arp->plen);
    printf("\n");
}

void print_tcp_layer(const unsigned char *packet, uint32_t caplen, uint32_t off)
{
    printf("\nL4 (TCP):\n");

    if (caplen < off + sizeof(struct tcp_hdr))
    {
        printf("Truncated TCP\n");
        return;
    }
    const struct tcp_hdr *tcp = (const struct tcp_hdr *)(packet + off);
    uint16_t src_port = ntohs(tcp->src_port);
    uint16_t dst_port = ntohs(tcp->dst_port);
    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack = ntohl(tcp->ack);
    uint8_t offset = (tcp->offset_reserved >> 4) * 4; // Data offset in bytes
    uint8_t flags = tcp->flags;
    uint16_t win = ntohs(tcp->win);
    uint16_t checksum = ntohs(tcp->checksum);
    uint16_t urg_ptr = ntohs(tcp->urg_ptr);
    char *application = "Unknown";
    if (dst_port == 80 || src_port == 80)
        application = "HTTP";
    else if (dst_port == 443 || src_port == 443)
        application = "HTTPS";
    else if (dst_port == 22 || src_port == 22)
        application = "SSH";
    else if (dst_port == 21 || src_port == 21)
        application = "FTP";
    else if (dst_port == 25 || src_port == 25)
        application = "SMTP";
    else if (dst_port == 53 || src_port == 53)
        application = "DNS";
    printf("Src Port: %u | Dst Port: %u (%s)\n", src_port, dst_port, application);
    printf("Sequence Number: %u | Acknowledgment Number: %u\n", seq, ack);
    printf("Window Size: %u | Checksum: 0x%04x | ", win, checksum);
    printf("TCP Header Length: %u bytes\n", offset);
    printf("Flags: [");
    if (flags & TH_FIN)
        printf("FIN ");
    if (flags & TH_SYN)
        printf("SYN ");
    if (flags & TH_RST)
        printf("RST ");
    if (flags & TH_PUSH)
        printf("PUSH ");
    if (flags & TH_ACK)
        printf("ACK ");
    if (flags & TH_URG)
        printf("URG ");
    if (flags & TH_ECE)
        printf("ECE ");
    if (flags & TH_CWR)
        printf("CWR ");
    if (flags & TH_NS)
        printf("NS ");
    printf("]\n");
    printf("\n");

    int tcp_header_len = offset;
    int payload_offset = off + tcp_header_len;
    int payload_len = caplen - payload_offset;

    if (payload_offset > caplen)
    {
        printf("Warning: TCP payload offset (%d) > caplen (%d)\n", payload_offset, caplen);
        return;
    }

    if (payload_len > 0)
    {
        const unsigned char *payload = packet + payload_offset;

        printf("L7 (Payload): Identified as %s on port %u - %d bytes\n", application, dst_port, payload_len);
        print_payload(payload, payload_len);
    }
    else
    {
        printf("No TCP Payload Detected (payload length = %d)\n", payload_len);
    }
}

void print_udp_layer(const unsigned char *packet, uint32_t caplen, uint32_t off)
{
    printf("\nL4 (UDP):\n");

    if (caplen < off + sizeof(struct udp_hdr))
    {
        printf("Truncated UDP\n");
        return;
    }

    const struct udp_hdr *udp = (const struct udp_hdr *)(packet + off);
    uint16_t src_port = ntohs(udp->src_port);
    uint16_t dst_port = ntohs(udp->dst_port);
    uint16_t len = ntohs(udp->len);
    uint16_t checksum = ntohs(udp->checksum);

    char *application = "Unknown";
    if (dst_port == 80 || src_port == 80)
    {
        application = "HTTP";
    }
    else if (dst_port == 443 || src_port == 443)
    {
        application = "HTTPS";
    }
    else if (dst_port == 53 || src_port == 53)
    {
        application = "DNS";
    }

    printf("Src Port: %u | Dst Port: %u (%s)\n", src_port, dst_port, application);
    printf("Length: %u bytes | Checksum: 0x%04x\n", len, checksum);
    printf("\n");

    int payload_offset = off + sizeof(struct udp_hdr);
    int payload_len = caplen - payload_offset;

    if (payload_offset > caplen)
    {
        printf("Warning: UDP payload offset (%d) > caplen (%d)\n", payload_offset, caplen);
        return;
    }

    if (payload_len > 0)
    {
        const unsigned char *payload = packet + payload_offset;

        printf("L7 (Payload): Identified as %s on port %u - %d bytes\n", application, dst_port, payload_len);
        print_payload(payload, payload_len);
    }
    else
    {
        printf("No UDP Payload Detected (payload length = %d)\n", payload_len);
    }
}

void print_payload(const unsigned char *payload, int payload_len)
{
    printf("L7 (Payload): ");

    if (payload_len <= 0)
    {
        printf("No data\n\n");
        return;
    }

    printf("%d bytes\n", payload_len);
    printf("Data (first %d bytes):\n", payload_len > 64 ? 64 : payload_len);

    int line_len = 16;
    for (int i = 0; i < payload_len && i < 64; i += line_len)
    {
        int j;
        for (j = 0; j < line_len && (i + j) < payload_len && (i + j) < 64; j++)
        {
            printf("%02X ", payload[i + j]);
        }
        if (j < line_len)
            for (; j < line_len; j++)
                printf("   ");

        printf(" ");
        for (j = 0; j < line_len && (i + j) < payload_len && (i + j) < 64; j++)
        {
            unsigned char c = payload[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("\n");
    }
    printf("-----------------------------------------\n\n");
}

// ================= Packet Handler =================

void packet_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    const unsigned char *ptr = packet;
    uint32_t caplen = header->caplen;

    if (caplen < sizeof(struct eth_hdr))
        return;

    uint32_t off = sizeof(struct eth_hdr);
    printf("\n===========================================\n");
    printf("Packet #%d\n", packet_id++);
    printf("Timestamp: %ld.%06ld | Length: %u bytes\n", header->ts.tv_sec, header->ts.tv_usec, header->caplen);
    printf("\n");

    // LLM Generated Code Begins
    // Phase - 1 (Printing the first 16 bytes of the packet)
    // printf("First 16 bytes:\n");
    // for (int i = 0; i < 16 && i < header->caplen; i++)
    // {
    //     printf("%02x ", packet[i]);
    //     if ((i + 1) % 8 == 0)
    //         printf(" ");
    // }
    // printf("\n");
    // LLM Generated Code Ends

    print_ethernet_layer(packet);

    unsigned short eth_type = (packet[12] << 8) | packet[13];

    if (eth_type == ETHER_TYPE_IPv4)
    {
        print_ipv4_layer(packet, caplen, off);
    }
    else if (eth_type == ETHER_TYPE_IPV6)
    {
        print_ipv6_layer(packet, caplen, off);
    }
    else if (eth_type == ETHER_TYPE_ARP)
    {
        print_arp_layer(packet, caplen, off);
    }
}

void sniffer(const char *d)
{
    handle = pcap_open_live(d, 65536, 1, 100, errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "[C-Shark] Couldn't open device %s: %s\n", d, errbuf);
        return;
    }

    signal(SIGINT, sigint_handler);

    printf("[C-Shark] Sniffing started on %s 🔍 ...\nPress Ctrl+C to return to Main Menu.\n", d);
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    if (stop_sniffing)
    {
        printf("[C-Shark] Ctrl+C pressed. Returning to Main Menu...\n");
        stop_sniffing = 0;
    }
}

int main()
{
    signal(SIGINT, sigint_handler);

    if (pcap_findalldevs(&alldevices, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }
    printf("[C-Shark] Welcome to C-Shark - A Simple Packet Sniffer\n");
    int ind = 1;
    pcap_if_t *d;

    printf("Searching for available network interfaces 🔍...\n");
    printf("--------------------------------\n");
    printf("[C-Shark] Available Network Interfaces:\n");
    for (d = alldevices; d != NULL; d = d->next)
    {
        printf("%d.%s", ind++, d->name);
        if (d->description)
        {
            printf(" (%s)\n", d->description);
        }
        else
        {
            printf("\n");
        }
    }
    int selected = -1;
    while (selected < 1 || selected > ind - 1) // While you enter the invalid selection, you can still select an interface (not exiting the program)
    {
        printf("--------------------------------\n");
        printf("[C-Shark] Enter the interface number (1-%d) to capture packets: ", ind - 1);

        if (scanf("%d", &selected) != 1)
        {
            printf("\n[C-Shark] Ctrl+D detected - Exiting C-Shark...\nThank You! Bye :)\n");
            return 0;
        }
        if (selected < 1 || selected > ind - 1)
        {
            printf("Invalid selection\n");
        }
        else
        {
            break;
        }
    }

    d = alldevices;
    for (int i = 1; i < selected; i++)
    {
        d = d->next;
    }
    device = d;
    printf("[C-Shark] Selected interface: %s\n", device->name);

    while (1)
    {

        printf("\n1. Start Sniffing all Packets\n2. Start Sniffing (With Filters)\n3. Inspect Last Session\n4. Exit C-Shark\n");
        printf("[C-Shark] Enter your choice: ");

        int mode;
        if (scanf("%d", &mode) != 1)
        {
            printf("\n[C-Shark] Ctrl+D detected - Exiting C-Shark...\nThank You! Bye :)\n");
            break;
        }
        if (mode > 4 || mode < 1)
        {
            printf("Invalid Choice.\n");
            continue;
        }
        if (mode == 4)
        {
            printf("[C-Shark] Exiting C-Shark...\nThank You! Bye :)\n");
            pcap_freealldevs(alldevices);
            return 0;
        }
        if (mode == 1)
        {
            sniffer(d->name);
        }
    }
    pcap_freealldevs(alldevices);
    return 0;
}