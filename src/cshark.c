#include "../include/cshark.h"

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

    // LLM Generated Code Begins
    uint8_t df_flag = (flags & 0x2) >> 1;
    uint8_t mf_flag = (flags & 0x1);
    // LLM Generated Code Ends

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
    // LLM Generated Code Begins
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
    // LLM Generated Code Ends
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
    // LLM Generated Code Begins
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
    // LLM Generated Code Ends
    printf("-----------------------------------------\n\n");
}

void print_summariser()
{
    // LLM Generated Code Begins
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
        char ports_str[16]; // Increased size to avoid truncation warning
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
    // LLM Generated Code Ends
}

void deep_hex_dump(const unsigned char *data, int len)
{
    int cols = 16;
    printf("┌───────────────────────────────────────────────────────────────────────────────────────┐\n");
    printf("│                              Full Packet Hex Dump (%d bytes)                          │\n", len);
    printf("├───────┬───────────────────────────────────────────────────────┬───────────────────────┤\n");
    printf("│ Offs  │ Hex                                                  │ ASCII                 │\n");
    printf("├───────┼───────────────────────────────────────────────────────┼───────────────────────┤\n");

    for (int i = 0; i < len; i += cols)
    {
        printf("│ %04x │ ", i);

        int j;
        for (j = 0; j < cols && (i + j) < len; j++)
            printf("%02X ", data[i + j]);
        for (; j < cols; j++)
            printf("   ");

        printf("│ ");

        for (j = 0; j < cols && (i + j) < len; j++)
        {
            unsigned char c = data[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }

        printf(" │\n");
    }

    printf("└───────┴───────────────────────────────────────────────────────┴───────────────────────┘\n");
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
    // LLM Generated Code Begins
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
    // LLM Generated Code Ends
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
    // LLM Generated Code Begins
    free_captured_packets();
    handle = pcap_open_live(d, 65536, 1, 100, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "[C-Shark] Couldn't open device %s: %s\n", d, errbuf);
        return;
    }
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

// ================= Deep Inspection Functions =================

static void deep_print_header(const char *title)
{
    int total = 89;
    int pad = total - 5 - (int)strlen(title);
    if (pad < 0) pad = 0;
    printf("┌─ %s ", title);
    for (int i = 0; i < pad; i++) printf("─");
    printf("┐\n");
    printf("│ %-9s │ %-30s │ %-19s │ %-19s │\n", "Offset", "Raw Hex", "Field", "Decoded Value");
    printf("├───────────┼────────────────────────────────┼─────────────────────┼─────────────────────┤\n");
}

static void deep_print_footer(void)
{
    printf("└───────────┴────────────────────────────────┴─────────────────────┴─────────────────────┘\n\n");
}

static void deep_print_row(const char *offset, const char *rawhex, const char *field, const char *value)
{
    printf("│ %-9s │ %-30s │ %-19s │ %-19s │\n", offset, rawhex, field, value);
}

void deep_ethernet(const unsigned char *packet)
{
    deep_print_header("Ethernet II");

    char offs[32], raw[64], fld[32], val[64];

    snprintf(offs, sizeof(offs), "00-05");
    snprintf(raw, sizeof(raw), "%02X:%02X:%02X:%02X:%02X:%02X",
             packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    snprintf(fld, sizeof(fld), "Destination MAC");
    snprintf(val, sizeof(val), "%02x:%02x:%02x:%02x:%02x:%02x",
             packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "06-11");
    snprintf(raw, sizeof(raw), "%02X:%02X:%02X:%02X:%02X:%02X",
             packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    snprintf(fld, sizeof(fld), "Source MAC");
    snprintf(val, sizeof(val), "%02x:%02x:%02x:%02x:%02x:%02x",
             packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    deep_print_row(offs, raw, fld, val);

    unsigned short eth_type = (packet[12] << 8) | packet[13];
    snprintf(offs, sizeof(offs), "12-13");
    snprintf(raw, sizeof(raw), "%02X:%02X", packet[12], packet[13]);
    snprintf(fld, sizeof(fld), "EtherType");
    const char *estr = "Unknown";
    if (eth_type == ETHER_TYPE_IPv4)       estr = "IPv4";
    else if (eth_type == ETHER_TYPE_IPV6)  estr = "IPv6";
    else if (eth_type == ETHER_TYPE_ARP)   estr = "ARP";
    snprintf(val, sizeof(val), "%s (0x%04x)", estr, eth_type);
    deep_print_row(offs, raw, fld, val);

    deep_print_footer();
}

void deep_ipv4(const unsigned char *packet, uint32_t caplen, uint32_t off)
{
    deep_print_header("Internet Protocol Version 4");

    if (caplen < off + sizeof(struct iphdr))
    {
        deep_print_row("N/A", "N/A", "ERROR", "Truncated IPv4");
        deep_print_footer();
        return;
    }

    const struct iphdr *ip = (const struct iphdr *)(packet + off);
    uint16_t iphdr_length = ip->ihl * 4;
    uint16_t frag_field = ntohs(ip->frag_off);
    uint8_t flags = (frag_field & 0xE000) >> 13;
    uint16_t frag_offset = frag_field & 0x1FFF;

    char offs[32], raw[64], fld[32], val[96];

    snprintf(offs, sizeof(offs), "%u", off);
    snprintf(raw, sizeof(raw), "%02X", packet[off]);
    snprintf(fld, sizeof(fld), "Version/IHL");
    snprintf(val, sizeof(val), "%u / %u (%u bytes)", ip->version, ip->ihl, iphdr_length);
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u", off + 1);
    snprintf(raw, sizeof(raw), "%02X", packet[off + 1]);
    snprintf(fld, sizeof(fld), "DSCP/ECN");
    snprintf(val, sizeof(val), "0x%02X", packet[off + 1]);
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 2, off + 3);
    snprintf(raw, sizeof(raw), "%02X:%02X", packet[off + 2], packet[off + 3]);
    snprintf(fld, sizeof(fld), "Total Length");
    snprintf(val, sizeof(val), "%u bytes", ntohs(ip->tot_len));
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 4, off + 5);
    snprintf(raw, sizeof(raw), "%02X:%02X", packet[off + 4], packet[off + 5]);
    snprintf(fld, sizeof(fld), "Identification");
    snprintf(val, sizeof(val), "0x%04x (%u)", ntohs(ip->id), ntohs(ip->id));
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 6, off + 7);
    snprintf(raw, sizeof(raw), "%02X:%02X", packet[off + 6], packet[off + 7]);
    snprintf(fld, sizeof(fld), "Flags/FragOff");
    char fbuf[32] = "";
    if (flags & 0x2) strcat(fbuf, "DF ");
    if (flags & 0x1) strcat(fbuf, "MF ");
    snprintf(val, sizeof(val), "[%s] offset=%u", fbuf, frag_offset);
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u", off + 8);
    snprintf(raw, sizeof(raw), "%02X", packet[off + 8]);
    snprintf(fld, sizeof(fld), "Time To Live");
    snprintf(val, sizeof(val), "%u", ip->ttl);
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u", off + 9);
    snprintf(raw, sizeof(raw), "%02X", packet[off + 9]);
    snprintf(fld, sizeof(fld), "Protocol");
    const char *proto;
    if (ip->protocol == IPPROTO_TCP)   proto = "TCP";
    else if (ip->protocol == IPPROTO_UDP)  proto = "UDP";
    else if (ip->protocol == IPPROTO_ICMP) proto = "ICMP";
    else proto = "Unknown";
    snprintf(val, sizeof(val), "%s (%u)", proto, ip->protocol);
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 10, off + 11);
    snprintf(raw, sizeof(raw), "%02X:%02X", packet[off + 10], packet[off + 11]);
    snprintf(fld, sizeof(fld), "Header Checksum");
    snprintf(val, sizeof(val), "0x%04x", ntohs(ip->check));
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 12, off + 15);
    snprintf(raw, sizeof(raw), "%02X:%02X:%02X:%02X",
             packet[off + 12], packet[off + 13], packet[off + 14], packet[off + 15]);
    snprintf(fld, sizeof(fld), "Source IP");
    char srcbuff[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->saddr, srcbuff, sizeof(srcbuff));
    snprintf(val, sizeof(val), "%s", srcbuff);
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 16, off + 19);
    snprintf(raw, sizeof(raw), "%02X:%02X:%02X:%02X",
             packet[off + 16], packet[off + 17], packet[off + 18], packet[off + 19]);
    snprintf(fld, sizeof(fld), "Destination IP");
    char dstbuff[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->daddr, dstbuff, sizeof(dstbuff));
    snprintf(val, sizeof(val), "%s", dstbuff);
    deep_print_row(offs, raw, fld, val);

    deep_print_footer();
}

void deep_ipv6(const unsigned char *packet, uint32_t caplen, uint32_t off)
{
    deep_print_header("Internet Protocol Version 6");

    if (caplen < off + sizeof(struct ip6_hdr))
    {
        deep_print_row("N/A", "N/A", "ERROR", "Truncated IPv6");
        deep_print_footer();
        return;
    }

    const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(packet + off);
    uint32_t flow = ntohl(ip6->ip6_flow);
    uint8_t traffic_class = (flow & 0x0FF00000) >> 20;
    uint32_t flow_label = (flow & 0x000FFFFF);

    char offs[32], raw[64], fld[32], val[96];

    snprintf(offs, sizeof(offs), "%u-%u", off, off + 3);
    snprintf(raw, sizeof(raw), "%02X:%02X:%02X:%02X",
             packet[off], packet[off + 1], packet[off + 2], packet[off + 3]);
    snprintf(fld, sizeof(fld), "Version/TC/Flow");
    snprintf(val, sizeof(val), "Ver=%u TC=%u Flow=0x%05x", (flow >> 28) & 0xF, traffic_class, flow_label);
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 4, off + 5);
    snprintf(raw, sizeof(raw), "%02X:%02X", packet[off + 4], packet[off + 5]);
    snprintf(fld, sizeof(fld), "Payload Length");
    snprintf(val, sizeof(val), "%u bytes", ntohs(ip6->ip6_plen));
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u", off + 6);
    snprintf(raw, sizeof(raw), "%02X", packet[off + 6]);
    snprintf(fld, sizeof(fld), "Next Header");
    const char *nxt;
    if (ip6->ip6_nxt == IPPROTO_TCP)      nxt = "TCP";
    else if (ip6->ip6_nxt == IPPROTO_UDP)  nxt = "UDP";
    else if (ip6->ip6_nxt == IPPROTO_ICMP) nxt = "ICMP";
    else nxt = "Unknown";
    snprintf(val, sizeof(val), "%s (%u)", nxt, ip6->ip6_nxt);
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u", off + 7);
    snprintf(raw, sizeof(raw), "%02X", packet[off + 7]);
    snprintf(fld, sizeof(fld), "Hop Limit");
    snprintf(val, sizeof(val), "%u", ip6->ip6_hlim);
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 8, off + 23);
    snprintf(raw, sizeof(raw), "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
             packet[off + 8], packet[off + 9], packet[off + 10], packet[off + 11],
             packet[off + 12], packet[off + 13], packet[off + 14], packet[off + 15],
             packet[off + 16], packet[off + 17], packet[off + 18], packet[off + 19],
             packet[off + 20], packet[off + 21], packet[off + 22], packet[off + 23]);
    snprintf(fld, sizeof(fld), "Source IP");
    char srcbuff[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6->ip6_src, srcbuff, sizeof(srcbuff));
    snprintf(val, sizeof(val), "%s", srcbuff);
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 24, off + 39);
    snprintf(raw, sizeof(raw), "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
             packet[off + 24], packet[off + 25], packet[off + 26], packet[off + 27],
             packet[off + 28], packet[off + 29], packet[off + 30], packet[off + 31],
             packet[off + 32], packet[off + 33], packet[off + 34], packet[off + 35],
             packet[off + 36], packet[off + 37], packet[off + 38], packet[off + 39]);
    snprintf(fld, sizeof(fld), "Destination IP");
    char dstbuff[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6->ip6_dst, dstbuff, sizeof(dstbuff));
    snprintf(val, sizeof(val), "%s", dstbuff);
    deep_print_row(offs, raw, fld, val);

    deep_print_footer();
}

void deep_arp(const unsigned char *packet, uint32_t caplen, uint32_t off)
{
    deep_print_header("Address Resolution Protocol");

    if (caplen < off + sizeof(struct ether_arp))
    {
        deep_print_row("N/A", "N/A", "ERROR", "Truncated ARP");
        deep_print_footer();
        return;
    }

    const struct ether_arp *arp = (const struct ether_arp *)(packet + off);

    char offs[32], raw[64], fld[32], val[96];

    snprintf(offs, sizeof(offs), "%u-%u", off, off + 1);
    snprintf(raw, sizeof(raw), "%02X:%02X", packet[off], packet[off + 1]);
    snprintf(fld, sizeof(fld), "Hardware Type");
    snprintf(val, sizeof(val), "%u", ntohs(arp->arp_hrd));
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 2, off + 3);
    snprintf(raw, sizeof(raw), "%02X:%02X", packet[off + 2], packet[off + 3]);
    snprintf(fld, sizeof(fld), "Protocol Type");
    snprintf(val, sizeof(val), "0x%04x", ntohs(arp->arp_pro));
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u", off + 4);
    snprintf(raw, sizeof(raw), "%02X", packet[off + 4]);
    snprintf(fld, sizeof(fld), "HW Length");
    snprintf(val, sizeof(val), "%u", arp->arp_hln);
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u", off + 5);
    snprintf(raw, sizeof(raw), "%02X", packet[off + 5]);
    snprintf(fld, sizeof(fld), "Proto Length");
    snprintf(val, sizeof(val), "%u", arp->arp_pln);
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 6, off + 7);
    snprintf(raw, sizeof(raw), "%02X:%02X", packet[off + 6], packet[off + 7]);
    snprintf(fld, sizeof(fld), "Operation");
    uint16_t oper = ntohs(arp->arp_op);
    const char *opstr = "Unknown";
    if (oper == ARPOP_REQUEST) opstr = "Request";
    else if (oper == ARPOP_REPLY) opstr = "Reply";
    snprintf(val, sizeof(val), "%s (%u)", opstr, oper);
    deep_print_row(offs, raw, fld, val);

    if (arp->arp_hln == 6)
    {
        snprintf(offs, sizeof(offs), "%u-%u", off + 8, off + 13);
        snprintf(raw, sizeof(raw), "%02X:%02X:%02X:%02X:%02X:%02X",
                 arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
                 arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
        snprintf(fld, sizeof(fld), "Sender MAC");
        snprintf(val, sizeof(val), "%02x:%02x:%02x:%02x:%02x:%02x",
                 arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
                 arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
        deep_print_row(offs, raw, fld, val);
    }

    if (arp->arp_pln == 4)
    {
        snprintf(offs, sizeof(offs), "%u-%u", off + 14, off + 17);
        snprintf(raw, sizeof(raw), "%02X:%02X:%02X:%02X",
                 arp->arp_spa[0], arp->arp_spa[1], arp->arp_spa[2], arp->arp_spa[3]);
        snprintf(fld, sizeof(fld), "Sender IP");
        snprintf(val, sizeof(val), "%d.%d.%d.%d",
                 arp->arp_spa[0], arp->arp_spa[1], arp->arp_spa[2], arp->arp_spa[3]);
        deep_print_row(offs, raw, fld, val);
    }

    if (arp->arp_hln == 6)
    {
        snprintf(offs, sizeof(offs), "%u-%u", off + 18, off + 23);
        snprintf(raw, sizeof(raw), "%02X:%02X:%02X:%02X:%02X:%02X",
                 arp->arp_tha[0], arp->arp_tha[1], arp->arp_tha[2],
                 arp->arp_tha[3], arp->arp_tha[4], arp->arp_tha[5]);
        snprintf(fld, sizeof(fld), "Target MAC");
        snprintf(val, sizeof(val), "%02x:%02x:%02x:%02x:%02x:%02x",
                 arp->arp_tha[0], arp->arp_tha[1], arp->arp_tha[2],
                 arp->arp_tha[3], arp->arp_tha[4], arp->arp_tha[5]);
        deep_print_row(offs, raw, fld, val);
    }

    if (arp->arp_pln == 4)
    {
        snprintf(offs, sizeof(offs), "%u-%u", off + 24, off + 27);
        snprintf(raw, sizeof(raw), "%02X:%02X:%02X:%02X",
                 arp->arp_tpa[0], arp->arp_tpa[1], arp->arp_tpa[2], arp->arp_tpa[3]);
        snprintf(fld, sizeof(fld), "Target IP");
        snprintf(val, sizeof(val), "%d.%d.%d.%d",
                 arp->arp_tpa[0], arp->arp_tpa[1], arp->arp_tpa[2], arp->arp_tpa[3]);
        deep_print_row(offs, raw, fld, val);
    }

    deep_print_footer();
}

const char *app_name_from_port(uint16_t port)
{
    if (port == 80)    return "HTTP";
    if (port == 443)   return "HTTPS";
    if (port == 22)    return "SSH";
    if (port == 21)    return "FTP";
    if (port == 25)    return "SMTP";
    if (port == 53)    return "DNS";
    if (port == 67 || port == 68) return "DHCP";
    if (port == 110)   return "POP3";
    if (port == 143)   return "IMAP";
    if (port == 3306)  return "MySQL";
    return "Unknown";
}

void deep_tcp(const unsigned char *packet, uint32_t caplen, uint32_t off)
{
    deep_print_header("Transmission Control Protocol");

    if (caplen < off + sizeof(struct tcphdr))
    {
        deep_print_row("N/A", "N/A", "ERROR", "Truncated TCP");
        deep_print_footer();
        return;
    }

    const struct tcphdr *tcp = (const struct tcphdr *)(packet + off);
    uint16_t src_port = ntohs(tcp->source);
    uint16_t dst_port = ntohs(tcp->dest);
    uint8_t doff = tcp->doff;
    uint16_t tcp_hdr_len = doff * 4;

    char offs[32], raw[64], fld[32], val[96];

    snprintf(offs, sizeof(offs), "%u-%u", off, off + 1);
    snprintf(raw, sizeof(raw), "%02X:%02X", packet[off], packet[off + 1]);
    snprintf(fld, sizeof(fld), "Source Port");
    snprintf(val, sizeof(val), "%u", src_port);
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 2, off + 3);
    snprintf(raw, sizeof(raw), "%02X:%02X", packet[off + 2], packet[off + 3]);
    snprintf(fld, sizeof(fld), "Destination Port");
    snprintf(val, sizeof(val), "%u (%s)", dst_port, app_name_from_port(dst_port));
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 4, off + 7);
    snprintf(raw, sizeof(raw), "%02X:%02X:%02X:%02X",
             packet[off + 4], packet[off + 5], packet[off + 6], packet[off + 7]);
    snprintf(fld, sizeof(fld), "Sequence Number");
    snprintf(val, sizeof(val), "%u", ntohl(tcp->seq));
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 8, off + 11);
    snprintf(raw, sizeof(raw), "%02X:%02X:%02X:%02X",
             packet[off + 8], packet[off + 9], packet[off + 10], packet[off + 11]);
    snprintf(fld, sizeof(fld), "Acknowledgment Num");
    snprintf(val, sizeof(val), "%u", ntohl(tcp->ack_seq));
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u", off + 12);
    snprintf(raw, sizeof(raw), "%02X", packet[off + 12]);
    snprintf(fld, sizeof(fld), "Data Offset");
    snprintf(val, sizeof(val), "%u words (%u bytes)", doff, tcp_hdr_len);
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u", off + 13);
    snprintf(raw, sizeof(raw), "%02X", packet[off + 13]);
    snprintf(fld, sizeof(fld), "Flags");
    char flagbuf[64] = "";
    if (tcp->fin) strcat(flagbuf, "FIN ");
    if (tcp->syn) strcat(flagbuf, "SYN ");
    if (tcp->rst) strcat(flagbuf, "RST ");
    if (tcp->psh) strcat(flagbuf, "PSH ");
    if (tcp->ack) strcat(flagbuf, "ACK ");
    if (tcp->urg) strcat(flagbuf, "URG ");
    if (strlen(flagbuf) > 0) flagbuf[strlen(flagbuf) - 1] = '\0';
    else strcpy(flagbuf, "None");
    snprintf(val, sizeof(val), "[%s]", flagbuf);
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 14, off + 15);
    snprintf(raw, sizeof(raw), "%02X:%02X", packet[off + 14], packet[off + 15]);
    snprintf(fld, sizeof(fld), "Window Size");
    snprintf(val, sizeof(val), "%u", ntohs(tcp->window));
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 16, off + 17);
    snprintf(raw, sizeof(raw), "%02X:%02X", packet[off + 16], packet[off + 17]);
    snprintf(fld, sizeof(fld), "Checksum");
    snprintf(val, sizeof(val), "0x%04x", ntohs(tcp->check));
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 18, off + 19);
    snprintf(raw, sizeof(raw), "%02X:%02X", packet[off + 18], packet[off + 19]);
    snprintf(fld, sizeof(fld), "Urgent Pointer");
    snprintf(val, sizeof(val), "%u", ntohs(tcp->urg_ptr));
    deep_print_row(offs, raw, fld, val);

    deep_print_footer();

    // Handle TCP payload
    int payload_offset = off + tcp_hdr_len;
    int payload_len = caplen - payload_offset;
    if (payload_len > 0)
    {
        const unsigned char *pload = packet + payload_offset;
        deep_payload(pload, payload_len, app_name_from_port(dst_port));
    }
}

void deep_udp(const unsigned char *packet, uint32_t caplen, uint32_t off)
{
    deep_print_header("User Datagram Protocol");

    if (caplen < off + sizeof(struct udphdr))
    {
        deep_print_row("N/A", "N/A", "ERROR", "Truncated UDP");
        deep_print_footer();
        return;
    }

    const struct udphdr *udp = (const struct udphdr *)(packet + off);
    uint16_t src_port = ntohs(udp->source);
    uint16_t dst_port = ntohs(udp->dest);

    char offs[32], raw[64], fld[32], val[96];

    snprintf(offs, sizeof(offs), "%u-%u", off, off + 1);
    snprintf(raw, sizeof(raw), "%02X:%02X", packet[off], packet[off + 1]);
    snprintf(fld, sizeof(fld), "Source Port");
    snprintf(val, sizeof(val), "%u", src_port);
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 2, off + 3);
    snprintf(raw, sizeof(raw), "%02X:%02X", packet[off + 2], packet[off + 3]);
    snprintf(fld, sizeof(fld), "Destination Port");
    snprintf(val, sizeof(val), "%u (%s)", dst_port, app_name_from_port(dst_port));
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 4, off + 5);
    snprintf(raw, sizeof(raw), "%02X:%02X", packet[off + 4], packet[off + 5]);
    snprintf(fld, sizeof(fld), "Length");
    snprintf(val, sizeof(val), "%u bytes", ntohs(udp->len));
    deep_print_row(offs, raw, fld, val);

    snprintf(offs, sizeof(offs), "%u-%u", off + 6, off + 7);
    snprintf(raw, sizeof(raw), "%02X:%02X", packet[off + 6], packet[off + 7]);
    snprintf(fld, sizeof(fld), "Checksum");
    snprintf(val, sizeof(val), "0x%04x", ntohs(udp->check));
    deep_print_row(offs, raw, fld, val);

    deep_print_footer();

    // Handle UDP payload
    int payload_offset = off + sizeof(struct udphdr);
    int payload_len = caplen - payload_offset;
    if (payload_len > 0)
    {
        const unsigned char *pload = packet + payload_offset;
        deep_payload(pload, payload_len, app_name_from_port(dst_port));
    }
}

void deep_payload(const unsigned char *payload, int len, const char *app_name)
{
    int total = 89;
    char title[64];
    snprintf(title, sizeof(title), "Payload (%s) - %d bytes", app_name, len);
    int pad = total - 5 - (int)strlen(title);
    if (pad < 0) pad = 0;
    printf("┌─ %s ", title);
    for (int i = 0; i < pad; i++) printf("─");
    printf("┐\n");

    int cols = 16;
    for (int i = 0; i < len; i += cols)
    {
        if (i % (cols * 8) == 0)
        {
            printf("│        ");
            for (int h = 0; h < cols; h++)
                printf("%02X ", h);
            printf(" │\n");
        }

        printf("│ %04x  ", i);

        int j;
        for (j = 0; j < cols && (i + j) < len; j++)
            printf("%02X ", payload[i + j]);
        for (; j < cols; j++)
            printf("   ");

        printf("│ ");

        for (j = 0; j < cols && (i + j) < len; j++)
        {
            unsigned char c = payload[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }

        printf(" │\n");
    }

    printf("└───────────────────────────────────────────────────────────────────────────────────────┘\n\n");
}

void inspect_packet(packet_store *sp)
{
    const unsigned char *packet = sp->data;
    uint32_t caplen = sp->header.caplen;

    int total = 89;
    printf("\n╔");
    for (int i = 0; i < total - 2; i++) printf("═");
    printf("╗\n");
    printf("║  %-76s  ║\n", "DEEP PACKET INSPECTION");
    printf("╠");
    for (int i = 0; i < total - 2; i++) printf("═");
    printf("╣\n");
    printf("║  Packet Length: %-8u bytes  |  Timestamp: %-20ld.%-6ld  ║\n",
           caplen, sp->header.ts.tv_sec, sp->header.ts.tv_usec);
    printf("╚");
    for (int i = 0; i < total - 2; i++) printf("═");
    printf("╝\n\n");

    deep_ethernet(packet);

    unsigned short eth_type = (packet[12] << 8) | packet[13];
    uint32_t off = sizeof(struct ether_header);

    if (eth_type == ETHER_TYPE_IPv4)
    {
        deep_ipv4(packet, caplen, off);
        const struct iphdr *ip = (const struct iphdr *)(packet + off);
        uint16_t iphdr_length = ip->ihl * 4;
        if (ip->protocol == IPPROTO_TCP)
            deep_tcp(packet, caplen, off + iphdr_length);
        else if (ip->protocol == IPPROTO_UDP)
            deep_udp(packet, caplen, off + iphdr_length);
    }
    else if (eth_type == ETHER_TYPE_IPV6)
    {
        deep_ipv6(packet, caplen, off);
        uint32_t l3off = off + sizeof(struct ip6_hdr);
        const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(packet + off);
        if (ip6->ip6_nxt == IPPROTO_TCP)
            deep_tcp(packet, caplen, l3off);
        else if (ip6->ip6_nxt == IPPROTO_UDP)
            deep_udp(packet, caplen, l3off);
    }
    else if (eth_type == ETHER_TYPE_ARP)
    {
        deep_arp(packet, caplen, off);
    }

    // Full hex dump
    deep_hex_dump(packet, caplen);
    printf("\n");
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
    while (selected < 1 || selected > ind - 1)
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