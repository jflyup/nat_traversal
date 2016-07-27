#include <stdint.h>

#include "nat_type.h"

typedef struct client client;
struct client {
    int sfd;
    uint32_t id;
    char buf[128];
    char* msg_buf;
    nat_type type;
    char ext_ip[16];
    uint16_t ext_port;
};

struct peer_info {
    char ip[16];
    uint16_t port;
    uint16_t type;
};

enum msg_type {     
     Enroll = 0x01,      
     GetPeerInfo = 0x02,     
     NotifyPeer = 0x03,      
 };

// public functions
int init(struct peer_info self, struct sockaddr_in punch_server, client* c);
int connect_to_peer(client* cli, uint32_t peer_id);
void on_connected(int sock);
