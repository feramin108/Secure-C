#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#define TIMEOUT 5 // Timeout in seconds
#define MAX_PORTS 65535 // Maximum port number to scan

int main(int argc, char *argv[]) {
    int sockfd, optval, i, j, count;
    struct sockaddr_in target_addr;
    struct timeval tv;
    fd_set readfds;
    char *target_ip, *scan_type;
    int start_port, end_port;

    // Check command line arguments
    if (argc != 4) {
        printf("Usage: %s <target IP> <scan type (TCP/UDP)> <port range (e.g. 1-1024)>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Parse command line arguments
    target_ip = argv[1];
    scan_type = argv[2];
    if (sscanf(argv[3], "%d-%d", &start_port, &end_port) != 2 || start_port < 1 || end_port > MAX_PORTS || start_port > end_port) {
        printf("Invalid port range\n");
        exit(EXIT_FAILURE);
    }

    // Create a socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Set the socket to non-blocking mode
    optval = 1;
    if (ioctl(sockfd, FIONBIO, &optval) < 0) {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }

    // Set the timeout value for select()
    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;

    // Loop through the port range and scan each port
    for (i = start_port; i <= end_port; i++) {
        // Set the target address and port
        memset(&target_addr, 0, sizeof(target_addr));
        target_addr.sin_family = AF_INET;
        target_addr.sin_addr.s_addr = inet_addr(target_ip);
        target_addr.sin_port = htons(i);

        // Connect to the target using the specified scan type
        if (strcmp(scan_type, "TCP") == 0) {
            if (connect(sockfd, (struct sockaddr *)&target_addr, sizeof(target_addr)) == 0) {
                printf("Port %d is open\n", i);
            }
        }
        else if (strcmp(scan_type, "UDP") == 0) {
            // Send an empty UDP packet to the target
            if (sendto(sockfd, NULL, 0, 0, (struct sockaddr *)&target_addr, sizeof(target_addr)) >= 0) {
                // Wait for a response using select()
                FD_ZERO(&readfds);
                FD_SET(sockfd, &readfds);
                count = select(sockfd + 1, &readfds, NULL, NULL, &tv);
                if (count > 0) {
                    printf("Port %d is open\n", i);
                }
            }
        }

        // Reset the socket to non-blocking mode
        optval = 1;
        if (ioctl(sockfd, FIONBIO, &optval) < 0) {
            perror("ioctl");
            exit(EXIT_FAILURE);
        }

        // Reset the timeout value for select()
        tv.tv_sec = TIMEOUT;
        tv.tv_usec = 0;
    }

    return 0;
}
