#include "cshark.h"

pcap_if_t *alldevices, *device;
char errbuf[PCAP_ERRBUF_SIZE];
static int packet_id = 1;

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("\n===========================================\n");
    printf("Packet #%d\n", packet_id++);
    // LLM Generated Code Begins
    printf("First 16 bytes:\n");
    for (int i = 0; i < 16 && i < header->caplen; i++)
    {
        printf("%02x ", packet[i]);
        if ((i + 1) % 8 == 0)
            printf(" ");
    }
    printf("\n");
    // LLM Generated Code Ends

    printf("\n");
    printf("Timestamp: %ld.%06ld | ", header->ts.tv_sec, header->ts.tv_usec);
    printf("Length: %u bytes\n", header->caplen);
}

int main()
{
    pcap_if_t *d; /* iterator over device list */

    if (pcap_findalldevs(&alldevices, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    int ind = 1;
    printf("[C-Shark] Welcome to C-Shark - A Simple Packet Sniffer\n");
    printf("Searching for available network interfaces 🔍...\n");
    printf("--------------------------------\n");
    printf("Found\n");
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
    printf("--------------------------------\n");
    printf("[C-Shark] Enter the interface number (1-%d) to capture packets: ", ind - 1);
    int selected;
    scanf("%d", &selected);
    if (selected < 1 || selected > ind - 1)
    {
        printf("Invalid selection\n");
        pcap_freealldevs(alldevices);
        return 1;
    }
    d = alldevices;
    for (int i = 1; i < selected; i++)
    {
        d = d->next;
    }
    device = d;
    printf("[C-Shark] Selected interface: %s\n", device->name);

    printf("1. Start Sniffing all Packets\n2. Start Sniffing (With Filters)\n3. Inspect Last Session\n4. Exit C-Shark\n");
    printf("[C-Shark] Enter your choice: ");

    int mode;
    scanf("%d", &mode);
    if (mode > 4 || mode < 1)
    {
        printf("Invalid Choice\n");
        pcap_freealldevs(alldevices);
        return 1;
    }
    if (mode == 4)
    {
        printf("[C-Shark] Exiting C-Shark. Goodbye!\n");
        pcap_freealldevs(alldevices);
        return 0;
    }
    if (mode == 1)
    {
        printf("[C-Shark] Starting Sniffing on %s 🔍 ...\n", device->name);
        pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
        pcap_loop(handle, -1, packet_handler, NULL);
        pcap_close(handle);
    }
    return 0;
}