#define SIO_KEEPALIVE_VALS _WSAIOW(IOC_VENDOR,4)

#define    SOCKS5_REPLY_OK                    0
#define    SOCKS5_REPLY_ERROR                1
#define    SOCKS5_REPLY_HOST_UNACCESSIBLE    4
#define    SOCKS5_REPLY_ERROR_CONNECT    5
#define    SOCKS5_REPLY_CMD_UNSUPPORT        7
#define    SOCKS5_REPLY_ADD_UNSUPPORT        8

#pragma pack(1)

struct tcp_keepalive {
	unsigned long  onoff;
	unsigned long  keepalivetime;
	unsigned long  keepaliveinterval;
};

typedef struct _S5_METHOD_REQ
{
    BYTE version;
    BYTE nmethods;
    BYTE methods[255];
} S5_METHOD_REQ, *PS5_METHOD_REQ;

typedef struct _S5_METHOD_RESP
{
    BYTE version;
    BYTE method;
}S5_METHOD_RESP, *PS5_METHOD_RESP;

typedef struct _S5_REQ
{
    BYTE version;
    BYTE command;
    BYTE reserved;
    BYTE atype;
    union
    {
        struct
        {
            ULONG addr;
            USHORT port;
        } ADDR_IP;
        struct
        {
            BYTE nlen;
            CHAR host[255];
        } ADDR_HOST;
    } ADDR_TYPE;
} S5_REQ, *PS5_REQ;

#pragma pack()

#undef RtlZeroMemory
void (__stdcall *RtlZeroMemory)(void *dst, int count);
#define HTONS(a) (((0xFF&a)<<8) + ((0xFF00&a)>>8))
int (__stdcall *tcp_func)(SOCKET s,char* buf,int len,int flags);

/*
#define HTOHL(x)(ULONG)((((ULONG)(x)<<24)&0xFF000000)^ \
	(((ULONG)(x)<< 8)&0x00FF0000)^ \
	(((ULONG)(x)>> 8)&0x0000FF00)^ \
	(((ULONG)(x)>>24)&0x000000FF))
*/
