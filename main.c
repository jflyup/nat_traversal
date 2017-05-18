#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "nat_traversal.h"

#define DEFAULT_SERVER_PORT 9988
#define MSG_BUF_SIZE 512

// use public stun servers to detect port allocation rule
static char *stun_servers[] = {
    "stun.ideasip.com",
    "stun.ekiga.net",
    "203.183.172.196"
};

// definition checked against extern declaration
int verbose = 0;

int main(int argc, char** argv)
{
    char* stun_server = stun_servers[0];
    char* local_host = "0.0.0.0";
    uint16_t stun_port = DEFAULT_STUN_SERVER_PORT;
    uint16_t local_port = DEFAULT_LOCAL_PORT;
    char* punch_server = NULL;
    uint32_t peer_id = 0;
    int ttl = 10;

    static char usage[] = "usage: [-h] [-H STUN_HOST] [-t ttl] [-P STUN_PORT] [-s punch server] [-d id] [-i SOURCE_IP] [-p SOURCE_PORT] [-v verbose]\n";
    int opt;
    while ((opt = getopt (argc, argv, "H:h:P:p:s:d:i")) != -1)
    {
        switch (opt)
        {
            case 'h':
                printf("%s", usage);
                break;
            case 'H':
                stun_server = optarg;
                break;
            case 't':
                ttl = atoi(optarg);
                break;
            case 'P':
                stun_port = atoi(optarg);
                break;
            case 's':
                punch_server = optarg;
                break;
            case 'p':
                local_port = atoi(optarg);
                break;
            case 'd':
                peer_id = atoi(optarg);
                break;
            case 'i':
                local_host = optarg;
                break;
            case 'v':
                verbose = 1;
            case '?':
            default:
                printf("invalid option: %c\n", opt);
                printf("%s", usage);

                return -1;
        }
    }

    char ext_ip[16] = {0};
    uint16_t ext_port = 0;

    // TODO we should try another STUN server if failed
    nat_type type = detect_nat_type(stun_server, stun_port, local_host, local_port, ext_ip, &ext_port);

    printf("NAT type: %s\n", get_nat_desc(type));
    if (ext_port) {
        printf("external address: %s:%d\n", ext_ip, ext_port);
    } else {
        return -1;
    }

    if (!punch_server) {
        printf("please specify punch server\n");
        return -1;
    }
    struct peer_info self;
    strncpy(self.ip, ext_ip, 16);
    self.port = ext_port;
    self.type = type;

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(punch_server);
    server_addr.sin_port = htons(DEFAULT_SERVER_PORT);

    client c;
    c.type = type;
    c.ttl = ttl;
    if (enroll(self, server_addr, &c) < 0) {
        printf("failed to enroll\n");

        return -1;
    }
    printf("enroll successfully, ID: %d\n", c.id);

    if (peer_id) {
        printf("connecting to peer %d\n", peer_id);
        if (connect_to_peer(&c, peer_id) < 0) {
            printf("failed to connect to peer %d\n", peer_id);

            return -1;
        }
    }

    pthread_t tid = wait_for_command(&c.sfd);

    pthread_join(tid, NULL);
    return 0;
}
