#include <stdint.h>

typedef enum {
    Blocked,
    OpenInternet,
    FullCone,
    RestricNAT,
    RestricPortNAT,
    SymmetricNAT,
    Error,
} nat_type;

#define DEFAULT_STUN_SERVER_PORT 3478
#define DEFAULT_LOCAL_PORT 34780
#define MAX_STUN_MESSAGE_LENGTH 512

// const static constants cannot be used in case label
#define MappedAddress 0x0001
#define SourceAddress 0x0004
#define ChangedAddress 0x0005

// define stun constants
const static uint8_t  IPv4Family = 0x01;
const static uint8_t  IPv6Family = 0x02;

const static uint32_t ChangeIpFlag   = 0x04;
const static uint32_t ChangePortFlag = 0x02;

const static uint16_t BindRequest      = 0x0001;
const static uint16_t BindResponse     = 0x0101;

const static uint16_t ResponseAddress  = 0x0002;
const static uint16_t ChangeRequest    = 0x0003; /* removed from rfc 5389.*/
const static uint16_t MessageIntegrity = 0x0008;
const static uint16_t ErrorCode        = 0x0009;
const static uint16_t UnknownAttribute = 0x000A;
const static uint16_t XorMappedAddress = 0x0020;

typedef struct { uint32_t longpart[4]; }  UInt128;
typedef struct { uint32_t longpart[3]; }  UInt96;

typedef struct 
{
    uint32_t magicCookie; // rfc 5389
    UInt96 tid;
} Id;

typedef struct 
{
    uint16_t msgType;
    uint16_t msgLength; // length of stun body
    union
    {
        UInt128 magicCookieAndTid;
        Id id;
    };
} StunHeader;

typedef struct
{
    uint16_t type;
    uint16_t length;
} StunAtrHdr;

typedef struct
{
    uint8_t family;
    uint16_t port;
    union
    {
        uint32_t ipv4;  // in host byte order
        UInt128 ipv6; // in network byte order
    } addr;
} StunAtrAddress;

char* encode16(char* buf, uint16_t data);
char* encode32(char* buf, uint32_t data);
char* encode(char* buf, const char* data, unsigned int length);
extern int verbose;

#define verbose_log(format, ...) do {       \
        if (verbose)                        \
            printf(format, ##__VA_ARGS__);  \
} while(0)

nat_type detect_nat_type(const char* stun_host, uint16_t stun_port, const char* local_host, uint16_t local_port, char* ext_ip, uint16_t* ext_port);

const char* get_nat_desc(nat_type type);
