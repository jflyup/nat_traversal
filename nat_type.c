#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#include "nat_type.h"

static const char* nat_types[] = {
	"blocked",
	"open internet",
	"full cone",
	"restricted NAT",
	"port-restricted cone",
	"symmetric NAT",
	"error"
};

char* encode16(char* buf, uint16_t data)
{
	uint16_t ndata = htons(data);
	memcpy(buf, (void*)(&ndata), sizeof(uint16_t));
	return buf + sizeof(uint16_t);
}

char* encode32(char* buf, uint32_t data)
{
	uint32_t ndata = htonl(data);
	memcpy(buf, (void*)(&ndata), sizeof(uint32_t));

	return buf + sizeof(uint32_t);
}

char* encodeAtrUInt32(char* ptr, uint16_t type, uint32_t value)
{
	ptr = encode16(ptr, type);
	ptr = encode16(ptr, 4);
	ptr = encode32(ptr, value);

	return ptr;
}

char* encode(char* buf, const char* data, unsigned int length)
{
	memcpy(buf, data, length);
	return buf + length;
}

static int stun_parse_atr_addr( char* body, unsigned int hdrLen, StunAtrAddress* result )
{
	if (hdrLen != 8 /* ipv4 size */ && hdrLen != 20 /* ipv6 size */ ) {
		return -1;
	}
	body++;  // Skip pad
	result->family = *body++;

	uint16_t nport;
	memcpy(&nport, body, 2);
    body+=2;
	result->port = ntohs(nport);

	if (result->family == IPv4Family) {		
		uint32_t naddr;
		memcpy(&naddr, body, sizeof(uint32_t)); body+=sizeof(uint32_t);
		result->addr.ipv4 = ntohl(naddr);
		// Note:  addr.ipv4 is stored in host byte order
		return 0;
	} else if (result->family == IPv6Family) {
		printf("ipv6 is not implemented yet");
	}

	return -1;
}

static void gen_random_string(char *s, const int len) {
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	int i = 0;
	for (; i < len; ++i) {
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	s[len] = 0;
}

static int send_bind_request(int sock, const char* remote_host, uint16_t remote_port, uint32_t change_ip, uint32_t change_port, StunAtrAddress* addr_array) {
	char* buf = malloc(MAX_STUN_MESSAGE_LENGTH);
	char* ptr = buf;

	StunHeader h;
	h.msgType = BindRequest;
	
	gen_random_string((char*)&h.magicCookieAndTid, 16);

	ptr = encode16(ptr, h.msgType);
	char* lengthp = ptr;
	ptr = encode16(ptr, 0);
	ptr = encode(ptr, (const char*)&h.id, sizeof(h.id));

	if (change_ip || change_port) {
		ptr = encodeAtrUInt32(ptr, ChangeRequest, change_ip | change_port);

		// length of stun body
		encode16(lengthp, ptr - buf - sizeof(StunHeader));
	}

    struct hostent *server = gethostbyname(remote_host);
	if (server == NULL) {
		fprintf(stderr, "no such host, %s\n", remote_host);
        free(buf);

		return -1;
	}
	struct sockaddr_in remote_addr;

	remote_addr.sin_family = AF_INET;
	memcpy(&remote_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
	remote_addr.sin_port = htons(remote_port); 

	if (-1 == sendto(sock, buf, ptr - buf, 0, (struct sockaddr *)&remote_addr, sizeof(remote_addr))) {
        free(buf);

		return -1;
	}

	socklen_t fromlen = sizeof remote_addr;

	struct timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

	if (recvfrom(sock, buf, 512, 0, (struct sockaddr *)&remote_addr, &fromlen) <= 0) {
        free(buf);

		return -1;
	}

	StunHeader reply_header;
	memcpy(&reply_header, buf, sizeof(StunHeader));

	uint16_t msg_type = ntohs(reply_header.msgType);

	if (msg_type == BindResponse) {
        char* body = buf + sizeof(StunHeader);
        uint16_t size = ntohs(reply_header.msgLength);

        StunAtrHdr* attr;
        unsigned int attrLen;
        unsigned int attrLenPad;  
        int atrType;

        while (size > 0) {
            attr = (StunAtrHdr*)(body);

            attrLen = ntohs(attr->length);
            // attrLen may not be on 4 byte boundary, in which case we need to pad to 4 bytes when advancing to next attribute
            attrLenPad = attrLen % 4 == 0 ? 0 : 4 - (attrLen % 4);  
            atrType = ntohs(attr->type);

            if ( attrLen + attrLenPad + 4 > size ) {
                free(buf);

                return -1;
            }

            body += 4; // skip the length and type in attribute header
            size -= 4;

            switch (atrType) {
            case MappedAddress:
                if (stun_parse_atr_addr(body, attrLen, addr_array)) {
                    free(buf);

                    return -1;
                }
                break;
            case ChangedAddress:
                if (stun_parse_atr_addr( body, attrLen, addr_array + 1)) {
                    free(buf);

                    return -1;
                }
                break;
            case SourceAddress:
                if (stun_parse_atr_addr( body, attrLen, addr_array + 2)) {
                    free(buf);

                    return -1;
                }
                break;
            default:
                // ignore
                break;
            }
            body += attrLen + attrLenPad;
            size -= attrLen + attrLenPad;
        }
    }
	
	free(buf);

	return 0;
}

const char* get_nat_desc(nat_type type) {
	return nat_types[type];
}

nat_type detect_nat_type(const char* stun_host, uint16_t stun_port, const char* local_host, uint16_t local_port, char* ext_ip, uint16_t* ext_port) {
    uint32_t mapped_ip = 0;
    uint16_t mapped_port = 0;
	int s;
	if((s = socket(AF_INET, SOCK_DGRAM, 0)) <= 0)  {  
		return Error;  
	}

    nat_type nat_type;

	int reuse_addr = 1;

	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse_addr, sizeof(reuse_addr));

	struct sockaddr_in local_addr;
	local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = inet_addr(local_host);

	local_addr.sin_port = htons(local_port);  
	if (bind(s, (struct sockaddr *)&local_addr, sizeof(local_addr))) {
        if (errno == EADDRINUSE) {
            printf("addr in use, try another port\n");
            nat_type = Error;
            goto cleanup_sock;
        }
    }

	// 0 for mapped addr, 1 for changed addr
	StunAtrAddress bind_result[2];

	memset(bind_result, 0, sizeof(StunAtrAddress) * 2);
	if (send_bind_request(s, stun_host, stun_port, 0, 0, bind_result)) {
		nat_type = Blocked;
        goto cleanup_sock;
	}

	mapped_ip = bind_result[0].addr.ipv4; // in host byte order
	mapped_port = bind_result[0].port;
	uint32_t changed_ip = bind_result[1].addr.ipv4;
	uint16_t changed_port = bind_result[1].port;

    struct in_addr mapped_addr;
    mapped_addr.s_addr = htonl(mapped_ip);

    /*
    * it's complicated to get the RECEIVER address of UDP packet,
    * For Linux, use the setsockopt() called IP_PKTINFO 
    * which will get you a parameter over recvmsg() called 
    * IP_PKTINFO, which carries a struct in_pktinfo, 
    * which has a 4 byte IP address hiding in its ipi_addr field.
    */

    /* TODO use getifaddrs() to get interface address, 
    * then compare it with mapped address to determine
    * if it's open internet
    */

	if (!strcmp(local_host, inet_ntoa(mapped_addr))) {
        nat_type = OpenInternet;
		goto cleanup_sock;
	} else { 
		if (changed_ip != 0 && changed_port != 0) {
			if (send_bind_request(s, stun_host, stun_port, ChangeIpFlag, ChangePortFlag, bind_result)) {
				struct in_addr addr = {changed_ip};
				char* alt_host = inet_ntoa(addr);

				memset(bind_result, 0, sizeof(StunAtrAddress) * 2);

				if (send_bind_request(s, alt_host, changed_port, 0, 0, bind_result)) {
					printf("failed to send request to alterative server\n");
                    nat_type = Error;
                    goto cleanup_sock;
				}

				if (mapped_ip != bind_result[0].addr.ipv4 || mapped_port != bind_result[0].port) {
					nat_type = SymmetricNAT;
                    goto cleanup_sock;
				}

				if (send_bind_request(s, alt_host, changed_port, 0, ChangePortFlag, bind_result)) {
					nat_type = RestricPortNAT;
                    goto cleanup_sock;
				}

				nat_type = RestricNAT;
                goto cleanup_sock;
			}
			else {
				nat_type = FullCone;	
                goto cleanup_sock;
			}
		} else {
			printf("no alterative server, can't detect nat type\n");
			nat_type = Error;
            goto cleanup_sock;
		}
	}
cleanup_sock:
    close(s);
    struct in_addr ext_addr;
    ext_addr.s_addr = htonl(mapped_ip);
    strcpy(ext_ip, inet_ntoa(ext_addr));
    *ext_port = mapped_port;

    return nat_type;
}
