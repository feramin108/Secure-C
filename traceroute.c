#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define MAX_HOPS 30
#define PACKET_SIZE 64

int main(int argc, char *argv[]) {
    int sockfd, ttl, seq_num = 1, recv_len, done = 0;
    char recv_buf[512], dest_ip[INET_ADDRSTRLEN];
    struct sockaddr_in target_addr, recv_addr;
    struct icmphdr icmp_hdr;
    struct iphdr ip_hdr;

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
    inet_pton(AF
// Loop through the TTL values and send ICMP packets with increasing TTLs
for (ttl = 1; ttl <= MAX_HOPS && !done; ttl++) {
    // Set the TTL value on the socket
    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Set the ICMP sequence number and checksum
    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.type = ICMP_ECHO;
    icmp_hdr.code = 0;
    icmp_hdr.un.echo.id = getpid();
    icmp_hdr.un.echo.sequence = seq_num++;
    icmp_hdr.checksum = 0;
    icmp_hdr.checksum = htons(~(0xffff & (icmp_hdr.type + icmp_hdr.code + icmp_hdr.un.echo.id + icmp_hdr.un.echo.sequence + PACKET_SIZE)));

    // Send the ICMP packet
    if (sendto(sockfd, &icmp_hdr, sizeof(icmp_hdr), 0, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }

    // Wait for an ICMP reply
    if ((recv_len = recvfrom(sockfd, &recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&recv_addr, &sizeof(recv_addr))) < 0) {
        perror("recvfrom");
        exit(EXIT_FAILURE);
    }

    // Extract the IP header and ICMP header from the received packet
    memcpy(&ip_hdr, recv_buf, sizeof(ip_hdr));
    memcpy(&icmp_hdr, recv_buf + sizeof(ip_hdr), sizeof(icmp_hdr));

    // Check if the target address was reached
    if (icmp_hdr.type == ICMP_ECHOREPLY) {
        done = 1;
    }

    // Print the hop number, IP address, and round-trip time
    inet_ntop(AF_INET, &recv_addr.sin_addr, dest_ip, sizeof(dest_ip));
    printf("%d. %s (%s)\n", ttl, dest_ip, (done ? "target reached" : "in transit"));
}

return 0;
