#include "cshark.h"

pcap_if_t *alldevices, *device;
char errbuf[PCAP_ERRBUF_SIZE];
static int packet_id = 1;
pcap_t *handle;
packet_store packets[MAX_PACKETS];
int packet_count = 0;

// LLM Generated Code Begins
volatile sig_atomic_t stop_sniffing = 0;

void sigint_handler(int sig)
{
    (void)sig; // Suppress unused parameter warning
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

    if (caplen < off + sizeof(struct iphdr))
    {
        printf("Truncated IPV4\n");
        return;
    }

    const struct iphdr *ip = (const struct iphdr *)(packet + off);
    uint8_t version = (ip->version);
    uint8_t ihl = (ip->ihl);
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
    inet_ntop(AF_INET, &ip->saddr, srcbuff, sizeof(srcbuff));
    inet_ntop(AF_INET, &ip->daddr, dstbuff, sizeof(dstbuff));
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
    printf("Packet ID: 0x%04x | Header Length: %u bytes | Total Length: %u\n", ntohs(ip->id), iphdr_length, ip_totlen);
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

    if (caplen < off + sizeof(struct ip6_hdr))
    {
        printf("Truncated IPV6\n");
        return;
    }

    const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(packet + off);
    uint8_t version = (ntohl(ip6->ip6_flow) >> 28);
    if (version != 6)
    {
        printf("Not IPv6 (ver=%u)\n", version);
        return;
    }

    char srcbuff[INET6_ADDRSTRLEN], dstbuff[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6->ip6_src, srcbuff, sizeof(srcbuff));
    inet_ntop(AF_INET6, &ip6->ip6_dst, dstbuff, sizeof(dstbuff));

    const char *proto;
    if (ip6->ip6_nxt == IPPROTO_TCP)
    {
        proto = "TCP";
    }
    else if (ip6->ip6_nxt == IPPROTO_UDP)
    {
        proto = "UDP";
    }
    else if (ip6->ip6_nxt == IPPROTO_ICMP)
    {
        proto = "ICMP";
    }
    else
    {
        proto = "Unknown";
    }

    printf("Src IP: %s | Dst IP: %s | Next Header: %s (%u)\n", srcbuff, dstbuff, proto, ip6->ip6_nxt);
    printf("Payload Length: %u bytes | Hop Limit: %u\n", ntohs(ip6->ip6_plen), ip6->ip6_hlim);

    uint8_t traffic_class = (ntohl(ip6->ip6_flow) & 0x0FF00000) >> 20;
    uint32_t flow_label = (ntohl(ip6->ip6_flow) & 0x000FFFFF);
    printf("Traffic Class: %u | Flow Label: 0x%05x\n", traffic_class, flow_label);
    printf("\n");
    int flag = 0;

    if (ip6->ip6_nxt == IPPROTO_TCP)
    {
        flag = 1;
        print_tcp_layer(packet, caplen, off + sizeof(struct ip6_hdr));
    }
    else if (ip6->ip6_nxt == IPPROTO_UDP)
    {
        flag = 1;
        print_udp_layer(packet, caplen, off + sizeof(struct ip6_hdr));
    }
    if (ntohs(ip6->ip6_plen) > 0 && flag == 0)
    {
        print_payload(packet + off + sizeof(struct ip6_hdr), ntohs(ip6->ip6_plen));
    }
}

void print_arp_layer(const unsigned char *packet, uint32_t caplen, uint32_t off)
{
    printf("L3 (ARP):\n");

    if (caplen < off + sizeof(struct ether_arp))
    {
        printf("Truncated ARP\n");
        return;
    }

    const struct ether_arp *arp = (const struct ether_arp *)(packet + off);
    printf("Operation: ");
    uint16_t oper = ntohs(arp->arp_op);

    if (oper == ARPOP_REQUEST)
        printf("Request (1)\n");
    else if (oper == ARPOP_REPLY)
        printf("Reply (2)\n");
    else
        printf("Unknown (%u)\n", oper);

    printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x | ",
           arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2], arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
    printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp->arp_tha[0], arp->arp_tha[1], arp->arp_tha[2], arp->arp_tha[3], arp->arp_tha[4], arp->arp_tha[5]);
    printf("Sender IP: %d.%d.%d.%d | ",
           arp->arp_spa[0], arp->arp_spa[1], arp->arp_spa[2], arp->arp_spa[3]);
    printf("Target IP: %d.%d.%d.%d\n",
           arp->arp_tpa[0], arp->arp_tpa[1], arp->arp_tpa[2], arp->arp_tpa[3]);
    printf("HW Type: %u | Protocol Type: 0x%04x | HW Length: %u | Protocol Length: %u\n",
           ntohs(arp->arp_hrd), ntohs(arp->arp_pro), arp->arp_hln, arp->arp_pln);
    printf("\n");
}

void print_tcp_layer(const unsigned char *packet, uint32_t caplen, uint32_t off)
{
    printf("\nL4 (TCP):\n");

    if (caplen < off + sizeof(struct tcphdr))
    {
        printf("Truncated TCP\n");
        return;
    }
    const struct tcphdr *tcp = (const struct tcphdr *)(packet + off);
    uint16_t src_port = ntohs(tcp->source);
    uint16_t dst_port = ntohs(tcp->dest);
    uint32_t seq = ntohl(tcp->seq);
    uint32_t ack = ntohl(tcp->ack_seq);
    uint8_t offset = tcp->doff * 4; // Data offset in bytes
    uint16_t win = ntohs(tcp->window);
    uint16_t checksum = ntohs(tcp->check);
    // Note: urg_ptr is available but not displayed in summary
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
    if (tcp->fin)
        printf("FIN ");
    if (tcp->syn)
        printf("SYN ");
    if (tcp->rst)
        printf("RST ");
    if (tcp->psh)
        printf("PUSH ");
    if (tcp->ack)
        printf("ACK ");
    if (tcp->urg)
        printf("URG ");
    // ECE, CWR, NS flags - these may not be in all tcphdr definitions
    printf("]\n");
    printf("\n");

    int tcp_header_len = offset;
    int payload_offset = off + tcp_header_len;
    int payload_len = caplen - payload_offset;

    if ((uint32_t)payload_offset > caplen)
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

    if (caplen < off + sizeof(struct udphdr))
    {
        printf("Truncated UDP\n");
        return;
    }

    const struct udphdr *udp = (const struct udphdr *)(packet + off);
    uint16_t src_port = ntohs(udp->source);
    uint16_t dst_port = ntohs(udp->dest);
    uint16_t len = ntohs(udp->len);
    uint16_t checksum = ntohs(udp->check);

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

    int payload_offset = off + sizeof(struct udphdr);
    int payload_len = caplen - payload_offset;

    if ((uint32_t)payload_offset > caplen)
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

void print_summariser()
{
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                    PACKET SUMMARY - Total Packets: %-4d                                                       ║\n", packet_count);
    printf("╠═════╦════════════╦═══════════════════════╦═══════════════════════╦════════════════════════════════════╦════════════════════════════════════╦═══════════╣\n");
    printf("║ No. ║   Length   ║      Timestamp        ║      Src MAC          ║            Src IP                  ║            Dst IP                  ║   Ports   ║\n");
    printf("╠═════╬════════════╬═══════════════════════╬═══════════════════════╬════════════════════════════════════╬════════════════════════════════════╬═══════════╣\n");
    
    for (int i = 0; i < packet_count; i++)
    {
        const struct pcap_pkthdr *header = &packets[i].header;
        
        // Format MAC address
        char src_mac_str[18];
        snprintf(src_mac_str, sizeof(src_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 packets[i].src_mac[0], packets[i].src_mac[1], packets[i].src_mac[2],
                 packets[i].src_mac[3], packets[i].src_mac[4], packets[i].src_mac[5]);
        
        // Format timestamp
        char timestamp_str[22];
        snprintf(timestamp_str, sizeof(timestamp_str), "%ld.%06ld", header->ts.tv_sec, header->ts.tv_usec);
        
        // Format ports
        char ports_str[16];  // Increased size to avoid truncation warning
        if (packets[i].src_port != 0 || packets[i].dst_port != 0)
        {
            snprintf(ports_str, sizeof(ports_str), "%u->%u", packets[i].src_port, packets[i].dst_port);
        }
        else
        {
            snprintf(ports_str, sizeof(ports_str), "N/A");
        }
        
        // Format IP addresses (handle empty strings)
        const char *src_ip_display = (packets[i].src_ip[0] != '\0') ? packets[i].src_ip : "N/A";
        const char *dst_ip_display = (packets[i].dst_ip[0] != '\0') ? packets[i].dst_ip : "N/A";
        
        printf("║ %-3d ║ %-8u B ║ %-21s ║ %-21s ║ %-34s ║ %-34s ║ %-9s ║\n",
               i + 1,
               header->caplen,
               timestamp_str,
               src_mac_str,
               src_ip_display,
               dst_ip_display,
               ports_str);
    }
    
    printf("╚═════╩════════════╩═══════════════════════╩═══════════════════════╩════════════════════════════════════╩════════════════════════════════════╩═══════════╝\n");
    printf("\n");
}

void hex_dump(const unsigned char *data, int len)
{
    printf("      ");
    for (int i = 0; i < 16; i++)
    {
        printf("%02X ", i);
    }
    printf("\n");
    for (int i = 0; i < len; i++)
    {
        if (i % 16 == 0)
            printf("%04x: ", i);
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0)
        {
            printf(" ");
            for (int j = i - 15; j <= i; j++)
            {
                unsigned char c = data[j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
            printf("\n");
        }
    }
    printf("\n");
}

void packet_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    (void)user; // Suppress unused parameter warning
    uint32_t caplen = header->caplen;

    if (caplen < sizeof(struct ether_header))
        return;

    uint32_t off = sizeof(struct ether_header);
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

    if (packet_count < MAX_PACKETS)
    {
        packet_store *sp = malloc(sizeof(packet_store));
        if (sp)
        {
            sp->header = *header;
            sp->data = malloc(header->caplen);
            if (sp->data)
            {
                memcpy((unsigned char *)sp->data, packet, header->caplen);
            }
            sp->src_mac[0] = packet[6];
            sp->src_mac[1] = packet[7];
            sp->src_mac[2] = packet[8];
            sp->src_mac[3] = packet[9];
            sp->src_mac[4] = packet[10];
            sp->src_mac[5] = packet[11];
            sp->dst_mac[0] = packet[0];
            sp->dst_mac[1] = packet[1];
            sp->dst_mac[2] = packet[2];
            sp->dst_mac[3] = packet[3];
            sp->dst_mac[4] = packet[4];
            sp->dst_mac[5] = packet[5];
            sp->timestamp = header->ts;
            sp->length = header->caplen;
            
            // Initialize IP addresses to empty strings
            sp->src_ip[0] = '\0';
            sp->dst_ip[0] = '\0';
            sp->protocol = 0;
            sp->src_port = 0;
            sp->dst_port = 0;
            
            if (eth_type == ETHER_TYPE_IPv4)
            {
                const struct iphdr *ip = (const struct iphdr *)(packet + off);
                inet_ntop(AF_INET, &ip->saddr, sp->src_ip, sizeof(sp->src_ip));
                inet_ntop(AF_INET, &ip->daddr, sp->dst_ip, sizeof(sp->dst_ip));
                sp->protocol = ip->protocol;
                if (ip->protocol == IPPROTO_TCP)
                {
                    const struct tcphdr *tcp = (const struct tcphdr *)(packet + off + (ip->ihl * 4));
                    sp->src_port = ntohs(tcp->source);
                    sp->dst_port = ntohs(tcp->dest);
                }
                else if (ip->protocol == IPPROTO_UDP)
                {
                    const struct udphdr *udp = (const struct udphdr *)(packet + off + (ip->ihl * 4));
                    sp->src_port = ntohs(udp->source);
                    sp->dst_port = ntohs(udp->dest);
                }
            }
            else if (eth_type == ETHER_TYPE_IPV6)
            {
                const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(packet + off);
                inet_ntop(AF_INET6, &ip6->ip6_src, sp->src_ip, sizeof(sp->src_ip));
                inet_ntop(AF_INET6, &ip6->ip6_dst, sp->dst_ip, sizeof(sp->dst_ip));
                sp->protocol = ip6->ip6_nxt;
                if (ip6->ip6_nxt == IPPROTO_TCP)
                {
                    const struct tcphdr *tcp = (const struct tcphdr *)(packet + off + sizeof(struct ip6_hdr));
                    sp->src_port = ntohs(tcp->source);
                    sp->dst_port = ntohs(tcp->dest);
                }
                else if (ip6->ip6_nxt == IPPROTO_UDP)
                {
                    const struct udphdr *udp = (const struct udphdr *)(packet + off + sizeof(struct ip6_hdr));
                    sp->src_port = ntohs(udp->source);
                    sp->dst_port = ntohs(udp->dest);
                }
            }
            
            // Copy the fully populated structure to the packets array
            packets[packet_count++] = *sp;
            free(sp);
        }
    }
}

void sniffer(const char *d)
{
    free_captured_packets();
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
        packet_id = 1;
    }
}

void sniffer_with_filter(const char *d, const char *filter_exp)
{
    free_captured_packets();
    handle = pcap_open_live(d, 65536, 1, 100, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "[C-Shark] Couldn't open device %s: %s\n", d, errbuf);
        return;
    }
    // LLM Generated Code Begins
    struct bpf_program fp;
    bpf_u_int32 net, mask;

    if (pcap_lookupnet(d, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "[C-Shark] Couldn't get netmask for device %s: %s\n", d, errbuf);
        net = 0;
        mask = 0;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, mask) == -1)
    {
        fprintf(stderr, "[C-Shark] Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "[C-Shark] Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return;
    }

    printf("[C-Shark] Filter '%s' applied successfully. Starting filtered sniffing...\n", filter_exp);

    signal(SIGINT, sigint_handler);
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);

    if (stop_sniffing)
    {
        printf("[C-Shark] Ctrl+C pressed. Returning to Main Menu...\n");
        stop_sniffing = 0;
        packet_id = 1;
    }
    // LLM Generated Code Ends
}

void free_captured_packets()
{
    for (int i = 0; i < packet_count; i++)
    {
        if (packets[i].data)
        {
            free((void *)packets[i].data);
            packets[i].data = NULL;
        }
    }
    packet_count = 0;
}

void inspect_packet(packet_store *sp)
{
    const unsigned char *packet = sp->data;
    uint32_t caplen = sp->header.caplen;

    printf("\n========== Detailed Inspection ==========\n");
    printf("Packet Length: %u bytes | Timestamp: %ld.%06ld\n\n", caplen, sp->header.ts.tv_sec, sp->header.ts.tv_usec);

    // Print interpreted layers
    print_ethernet_layer(packet);

    unsigned short eth_type = (packet[12] << 8) | packet[13];
    uint32_t off = sizeof(struct ether_header);

    if (eth_type == ETHER_TYPE_IPv4)
        print_ipv4_layer(packet, caplen, off);
    else if (eth_type == ETHER_TYPE_IPV6)
        print_ipv6_layer(packet, caplen, off);
    else if (eth_type == ETHER_TYPE_ARP)
        print_arp_layer(packet, caplen, off);

    // Full hex dump
    printf("\nFull Hex Dump:\n");
    hex_dump(packet, caplen);
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

        printf("\n1. Start Sniffing all Packets 🔍\n2. Start Sniffing (With Filters) 🔍🔍\n3. Inspect Last Session\n4. Exit C-Shark\n");
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
        else if (mode == 4)
        {
            printf("[C-Shark] Exiting C-Shark...\nThank You! Bye :)\n");
            pcap_freealldevs(alldevices);
            return 0;
        }
        else if (mode == 1)
        {
            sniffer(d->name);
        }
        else if (mode == 2)
        {
            printf("[C-Shark] Welcome to Filtered Sniffing Mode!\n");
            int filter_choice = 0;

            while (filter_choice < 1 || filter_choice > 6)
            {
                printf("1. HTTP\n2. HTTPS\n3. DNS\n4. ARP\n5. TCP\n6. UDP\n");
                printf("[C-Shark] Select the filter for precision hunting: ");

                if (scanf("%d", &filter_choice) != 1)
                {
                    printf("\n[C-Shark] Ctrl+D detected - Exiting C-Shark...\nThank You! Bye :)\n");
                    break;
                }

                if (filter_choice < 1 || filter_choice > 6)
                {
                    printf("Invalid filter choice. Please select again.\n");
                }
            }

            char filter_exp[50];
            switch (filter_choice)
            {
            case 1:
                strcpy(filter_exp, "tcp port 80");
                break;
            case 2:
                strcpy(filter_exp, "tcp port 443");
                break;
            case 3:
                strcpy(filter_exp, "udp port 53");
                break;
            case 4:
                strcpy(filter_exp, "arp");
                break;
            case 5:
                strcpy(filter_exp, "tcp");
                break;
            case 6:
                strcpy(filter_exp, "udp");
                break;
            default:
                strcpy(filter_exp, "ip");
                break;
            }

            sniffer_with_filter(d->name, filter_exp);
        }
        else if (mode == 3)
        {
            if (packet_count == 0)
            {
                printf("[C-Shark] No packets captured yet. Start a sniffing session first.\n");
                continue;
            }
            printf("[C-Shark] Inspecting last session 🔍...\n%d packets captured.\n", packet_count);
            print_summariser();
            printf("\n[C-Shark] Enter packet number (1-%d) to inspect in detail or 0 to return to main menu: ", packet_count);
            int pkt_num;
            if (scanf("%d", &pkt_num) != 1)
            {
                printf("\n[C-Shark] Ctrl+D detected - Exiting C-Shark...\n");
                break;
            }
            if (pkt_num == 0)
            {
                continue;
            }
            while (pkt_num < 1 || pkt_num > packet_count)
            {
                printf("Invalid packet number. Please enter a number between 1 and %d or 0 to return: ", packet_count);
                if (scanf("%d", &pkt_num) != 1)
                {
                    printf("\n[C-Shark] Ctrl+D detected - Exiting C-Shark...\n");
                    break;
                }
                if (pkt_num == 0)
                {
                    break;
                }
            }
            inspect_packet(&packets[pkt_num - 1]);
        }
    }
    pcap_freealldevs(alldevices);

    free_captured_packets();

    return 0;
}