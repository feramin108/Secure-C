#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

#define SNAP_LEN 1518 // Maximum packet length to capture
#define FILTER_EXP "icmp" // Filter expression for packets to capture

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Print packet information
    printf("Packet length: %d\n", header->len);

    // Print packet data in hexadecimal format
    int i;
    for (i = 0; i < header->len; i++) {
        printf("%02x ", packet[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program filter;
    bpf_u_int32 mask, net;

    // Check command line arguments
    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Lookup network and netmask information for the specified interface
    if (pcap_lookupnet(argv[1], &net, &mask, errbuf) < 0) {
        printf("Error looking up network information: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    // Open the specified interface for capturing packets
    if ((handle = pcap_open_live(argv[1], SNAP_LEN, 1, 1000, errbuf)) == NULL) {
        printf("Error opening interface: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    // Compile the filter expression
    if (pcap_compile(handle, &filter, FILTER_EXP, 0, net) < 0) {
        printf("Error compiling filter expression: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // Set the filter for the capture handle
    if (pcap_setfilter(handle, &filter) < 0) {
        printf("Error setting filter: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // Capture packets and process them using the callback function
    if (pcap_loop(handle, -1, process_packet, NULL) < 0) {
        printf("Error capturing packets: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // Cleanup
    pcap_freecode(&filter);
    pcap_close(handle);

    return 0;
}
