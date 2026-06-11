# C-Shark: The Terminal Packet Sniffer

## Overview
C-Shark is a terminal-based packet sniffer written in C. It uses libpcap to discover local network interfaces, capture live traffic, and print a layered breakdown of each packet directly in the terminal.

The program is designed around a simple interactive menu. You first choose an interface, then start a live capture, optionally apply a basic packet filter, and finally inspect the packets that were captured in the most recent session.

## What It Shows
C-Shark prints packet details in a readable, protocol-focused format:

- Ethernet frame information
- IPv4, IPv6, and ARP headers
- TCP and UDP header fields
- Basic application hints for common ports such as HTTP, HTTPS, DNS, SSH, FTP, and SMTP
- Payload previews and hex dumps for deeper inspection
- A compact session summary for previously captured packets

## Requirements

- Linux
- GCC or another C compiler
- `make`
- libpcap development headers and library

On Debian or Ubuntu systems, the dependencies can usually be installed with:

```bash
sudo apt install build-essential libpcap-dev
```

## Build
The project is split into a small source and header layout:

- `src/cshark.c` contains the application logic
- `include/cshark.h` contains the shared declarations and protocol headers

A direct compile command is:

```bash
gcc -Wall -Wextra -Iinclude -o cshark src/cshark.c -lpcap -pthread
```

If you prefer to use `make`, keep the source path in the Makefile aligned with the repository layout.

## Run

```bash
./cshark
```

When the program starts, it will:

1. List the available network interfaces
2. Ask you to choose one interface for capture
3. Show a menu with capture and inspection options

## Menu Flow

1. Start sniffing all packets
2. Start sniffing with filters
3. Inspect the last capture session
4. Exit

When filtered capture is selected, C-Shark provides these presets:

- HTTP
- HTTPS
- DNS
- ARP
- TCP
- UDP

## Inspecting Captured Traffic
Captured packets are stored in memory for the current session. After a capture, you can open the session summary and inspect any packet in detail. The detailed view includes protocol headers and a hex dump of the packet payload.

## Project Layout

```text
.
├── Makefile
├── README.md
├── include/
│   └── cshark.h
└── src/
	└── cshark.c
```

## Notes

- Packet capture requires appropriate permissions on the selected interface.
- The current implementation focuses on live capture and in-memory session inspection.
- Use `Ctrl+C` to stop an active sniffing session and return to the main menu.