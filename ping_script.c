#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

int main(int argc, char *argv[]) {
    struct icmphdr icmp_hdr;
    struct sockaddr_in target_addr;
    char recv_buf[512];
    int sockfd, seq_num = 1, pid = getpid();

    // Check that a target address was provided
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <target_address>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Create a raw socket for ICMP packets
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Set the target address and ICMP header fields
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    inet_pton(AF_INET, argv[1], &target_addr.sin_addr);
    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.type = ICMP_ECHO;
    icmp_hdr.code = 0;
    icmp_hdr.un.echo.id = pid;

    while (1) {
        // Set the ICMP sequence number and checksum
        icmp_hdr.un.echo.sequence = seq_num++;
        icmp_hdr.checksum = 0;
        icmp_hdr.checksum = htons(~(0xffff & (pid + seq_num + icmp_hdr.type + icmp_hdr.code + sizeof(icmp_hdr))));

        // Send the ICMP packet
        if (sendto(sockfd, &icmp_hdr, sizeof(icmp_hdr), 0, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
            perror("sendto");
            exit(EXIT_FAILURE);
        }

        // Wait for an ICMP reply
        if (recv(sockfd, &recv_buf, sizeof(recv_buf), 0) > 0) {
            printf("Ping reply from %s\n", argv[1]);
        }

        sleep(1);
    }

    return 0;
}
