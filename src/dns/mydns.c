#include "stdhdr.h"
#include "mydns.h"
#include "log.h"

#define BUFSIZE 1024

static struct sockaddr_in dnsAddr;
static struct sockaddr_in myAddr;
/**
 * Initialize your client DNS library with the IP address and port number of
 * your DNS server.
 *
 * @param  dns_ip  The IP address of the DNS server.
 * @param  dns_port  The port number of the DNS server.
 * @param  client_ip  The IP address of the client
 *
 * @return 0 on success, -1 otherwise
 */
int init_mydns(const char *dns_ip, unsigned int dns_port, const char *client_ip){
    if (inet_aton(dns_ip, &dnsAddr.sin_addr) == 0)
    {
        logVerbose("Invalid dns server IP(%s).", dns_ip);
        return -1;
    }
    dnsAddr.sin_port = htons(dns_port);

    if (inet_aton(client_ip, &myAddr.sin_addr) == 0)
    {
        logVerbose("Invalid client IP(%s).", client_ip);
        return -1;
    }
    myAddr.sin_port = 0;

    return 0;
}

/* make connection to dns server */
static int mydns_netdial()
{
    socklen_t len = sizeof(struct sockaddr_in);
    int s;
    char errbuf[256];

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) 
    {
        logVerbose("Can't create socket(%s).", strerrorV(errno, errbuf));
        goto netdial_fail_final;
    }

    if (bind(s, (struct sockaddr*)&myAddr, len) < 0)
    {
        logVerbose("Can't bind socket to given client IP(%s).", 
            strerrorV(errno, errbuf));
        goto netdial_fail_free;
    }

    if (connect(s, (struct sockaddr*)&dnsAddr, len) < 0 && 
        errno != EINPROGRESS) 
    {
        logVerbose("Can't connect to given server(%s).", 
            strerrorV(errno, errbuf));
        goto netdial_fail_free;
    }

    return s;
netdial_fail_free:
    close(s);
netdial_fail_final:
    return -1;
}

char *atoqn(char *dest, const char *src)
{
    int wlen = 0;

    do
    {
        if (*src == '.' || *src == '\0')
        {
            *dest = wlen;
            dest += wlen + 1;
            wlen = 0;
            if (*src == '\0')
            {
                *dest = 0;
                break;
            }
        }
        else
        {
            *(dest + (++wlen)) = *src;
        }
    }
    while (src++);

    return dest + 1;
}

char *qntoa(char *dest, const char *src)
{
    while (*src)
    {
        memcpy(dest, src + 1, *src);
        dest[(int)*src] = '.';
        dest += *src + 1;
        src += *src + 1;
    }

    return dest;
}

static int generateRequest(const char *node, const char *service, void *pak)
{
    static lock_t id = 0;
    static const word qtype = 1;
    static const word qclass = 1;
    struct dnshdr* hdr = (struct dnshdr*)pak;
    char *qname = (char*)(pak + sizeof(struct dnshdr));

    // make gcc happy
    service = service + 1 - 1;

    hdr->id = htons(atomic_fetch_add_explicit(&id, 1, memory_order_relaxed));
    hdr->qr = 0;
    hdr->opcode = 0;
    hdr->aa = 0;
    hdr->tc = 0;
    hdr->rd = 0;
    hdr->ra = 0;
    hdr->z = 0;
    hdr->rcode = 0;
    hdr->qdcount = 1;
    hdr->ancount = 0;
    hdr->nscount = 0;
    hdr->arcount = 0;

    qname = atoqn(qname, node);

    *(qname++) = qtype >> 8;
    *(qname++) = qtype;
    *(qname++) = qclass >> 8;
    *(qname++) = qclass;

    return 0;
}

static inline int isReply(const void *spak, const void *rpak)
{
    struct dnshdr* shdr = (struct dnshdr*)spak;
    struct dnshdr* rhdr = (struct dnshdr*)rpak;

    return rhdr->id == shdr->id && rhdr->qr == 1;
}

#define FAIL_INVALID 1
static inline int isFailed(const void *spak, const void *rpak, int len)
{
    struct dnshdr* rhdr = (struct dnshdr*)rpak;

    if (rhdr->rcode != 0)
    {
        logVerbose("Query failed with rcode %d", rhdr->rcode);
        return rhdr->rcode;
    }
    if (rhdr->ancount == 0)
    {
        logVerbose("Server returning packet with no answers...");
        return FAIL_INVALID;
    }

    for (int i = sizeof(struct dnshdr); i < len; ++i)
    {
        if (*(char*)spak != *(char*)rpak)
        {
            logVerbose("Server not answering our question...");
            return FAIL_INVALID;
        }
    }

    return 0;
}

static int generateAddrinfo(const void *rpak, int off, struct addrinfo **res,
    const char *service)
{
    struct dnshdr* rhdr = (struct dnshdr*)rpak;
    char *pos = (char*)(rpak + off);
    word i = 0;
    struct addrinfo *ite;
    char buf[BUFSIZE];

    *res = malloc(sizeof(struct addrinfo));
    ite = *res;
    while (i < rhdr->ancount)
    {
        word type, class, ttl, rdlength;
        memset(ite, 0, sizeof(struct addrinfo));
        ite->ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;
        ite->ai_family = AF_INET;

        pos = qntoa(buf, pos);
        ite->ai_canonname = (char*)malloc(strlen(buf) + 1);
        strcpy(ite->ai_canonname, buf);

        type = (*(pos++) & 0x000000FFL) << 8;
        type |= *(pos++) & 0x000000FFL;
        class = (*(pos++) & 0x000000FFL) << 8;
        class |= *(pos++) & 0x000000FFL;
        ttl = (*(pos++) & 0x000000FFL) << 8;
        ttl |= *(pos++) & 0x000000FFL;
        rdlength = (*(pos++) & 0x000000FFL) << 8;
        rdlength |= *(pos++) & 0x000000FFL;

        if (type != 1 || class != 1 || ttl != 0 || rdlength != 4)
        {
            mydns_freeaddrinfo(ite);
            return -1;
        }

        ite->ai_addrlen = sizeof(struct sockaddr);
        ite->ai_addr = (struct sockaddr*)malloc(sizeof(struct sockaddr));
        ((struct sockaddr_in*)ite->ai_addr)->sin_family = AF_INET;
        ((struct sockaddr_in*)ite->ai_addr)->sin_port = htons(atoi(service));
        memcpy(ite->ai_addr + 4, pos, 4);

        if (++i != rhdr->ancount)
        {
            ite->ai_next = (struct addrinfo*)malloc(sizeof(struct addrinfo));
            ite = ite->ai_next;
        }
    }

    return 0;
}

/**
 * Resolve a DNS name using your custom DNS server.
 *
 * Whenever your proxy needs to open a connection to a web server, it calls
 * resolve() as follows:
 *
 * struct addrinfo *result;
 * int rc = resolve("video.pku.edu.cn", "8080", null, &result);
 * if (rc != 0) {
 *     // handle error
 * }
 * // connect to address in result
 * mydns_freeaddrinfo(result);
 *
 *
 * @param  node  The hostname to resolve.
 * @param  service  The desired port number as a string.
 * @param  hints  Should be null. resolve() ignores this parameter.
 * @param  res  The result. resolve() should allocate a struct addrinfo, which
 * the caller is responsible for freeing.
 *
 * @return 0 on success, -1 otherwise
 */

int resolve(const char *node, const char *service, 
            const struct addrinfo *hints, struct addrinfo **res)
{
    int attempt = 1;
    int sockfd;
    byte *sendBuf = malloc(BUFSIZE);
    byte *recvBuf = malloc(BUFSIZE);
    socklen_t slen = sizeof(struct sockaddr);
    int len;
    int rlen;
    int ret = -1;
    int send = 1;
    struct timeval timeout = {
        RTO_IN_US / 1000000, RTO_IN_US % 1000000 }; 
    char errorbuf[256];

    hints = hints + 1 - 1;

    if (node == NULL || service == NULL)
    {
        logVerbose("Using empty node(%s) or service(%s) string, return.",
            node, service);
        goto resolve_final;
    }

    logVerbose("Resolving IP address of %s:%s...", node, service);

    if ((len = generateRequest(node, service, sendBuf)) == 0)
    {
        logVerbose("Failed to generate request, return.");
        goto resolve_final;
    }
    dumpDNSPacket(sendBuf, len);

    if ((sockfd = mydns_netdial() == -1))
    {
        logVerbose("Can't connect to name server, return.");
        goto resolve_final;
    } 

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, 
        (char*)&timeout, sizeof(struct timeval)) == -1)
    {
        logVerbose("Can't set socket receive timeout(%s), return.", 
            strerrorV(errno, errorbuf));
        goto resolve_final;
    }

    for (; attempt <= MAX_ATTEMPT; attempt += send)
    {
        int queryret;
        if (send && sendto(sockfd, sendBuf, len, 0, 
            (struct sockaddr*)&dnsAddr, (socklen_t)slen) == -1)
        {
            logVerbose("Can't send packet(%s), return.", 
                strerrorV(errno, errorbuf));
            goto resolve_fail_close;
        }

        if ((rlen = recvfrom(sockfd, recvBuf, BUFSIZE, 0, 
            (struct sockaddr*)&dnsAddr, &slen)) == -1)
        {
            if (errno == EAGAIN || errno == ECONNREFUSED)
            {
                logVerbose("Seems like a timeout, ignore.");
                continue;
            }
            logVerbose("Can't receive packet(%s), return.", 
                strerrorV(errno, errorbuf));
            goto resolve_fail_close;
        }
        dumpDNSPacket(recvBuf, rlen);

        if (!isReply(sendBuf, recvBuf))
        {
            logVerbose("Receiving strange packet, ignore.");
            send = 0;
            continue;
        }

        if ((queryret = isFailed(sendBuf, recvBuf, len)) != 0)
        {
            logVerbose("Query failed, return.");
            goto resolve_fail_close;
        }

        if (generateAddrinfo(recvBuf, len, res, service) != -1)
        {
            logVerbose("Failed to generate result, return.");
            break;
        }

        send = 1;
    }

    if (attempt <= MAX_ATTEMPT)
    {
        ret = 0;
    }
    else
    {
        logVerbose("Failed for too many times, return.");
    }

resolve_fail_close:
    close(sockfd);
resolve_final:
    return ret;
}

/**
 * Release the addrinfo structure.
 *
 * @param  p  the addrinfo structure to release
 *
 * @return 0 on success, -1 otherwise
 */
int mydns_freeaddrinfo(struct addrinfo *p)
{
    while (p)
    {
        struct addrinfo *tp = p;
        if (p->ai_canonname)
        {
            free(p->ai_canonname);
        }
        if (p->ai_addr)
        {
            free(p->ai_addr);
        }
        p = p->ai_next;
        free(tp);
    }

    return 0;
}

void dumpDNSPacket(const void *pak, int len)
{
    const struct dnshdr *hdr = (const struct dnshdr*)pak;
    int i;
    const char *pos;
    char namebuf[BUFSIZE];
    logMessage("Dumping packet with len=%d", len);
    logMessage("Packet header:");
    logMessage("  ->id: %x", hdr->id);
    logMessage("  ->rcode: %x", hdr->rcode);
    logMessage("  ->z: %x", hdr->z);
    logMessage("  ->ra: %x", hdr->ra);
    logMessage("  ->rd: %x", hdr->rd);
    logMessage("  ->tc: %x", hdr->tc);
    logMessage("  ->aa: %x", hdr->aa);
    logMessage("  ->opcode: %x", hdr->opcode);
    logMessage("  ->qr: %u", hdr->qr);
    logMessage("  ->qdcount: %u", hdr->qdcount);
    logMessage("  ->ancount: %u", hdr->ancount);
    logMessage("  ->nscount: %u", hdr->nscount);
    logMessage("  ->arcount: %u", hdr->arcount);

    pos = (const char*)pak + sizeof(struct dnshdr);
    for (i = 0; i < hdr->qdcount; ++i)
    {
        int qtype;
        int qclass;
        logMessage("  ->Message #%d:", i);
        pos = qntoa(namebuf, pos);
        qtype = (*(pos++) & 0x000000FFL) << 8;
        qtype |= *(pos++) & 0x000000FFL;
        qclass = (*(pos++) & 0x000000FFL) << 8;
        qclass |= *(pos++) & 0x000000FFL;
        logMessage("    ->name: %s", namebuf);
        logMessage("    ->qtype: %x", qtype);
        logMessage("    ->qclass: %x", qclass);
    }

    for (i = 0; i < hdr->ancount; ++i)
    {
        int type;
        int class;
        int ttl;
        int rdlength;
        char *rd = namebuf;
        logMessage("  ->Answer #%d", i);
        pos = qntoa(namebuf, pos);
        type = (*(pos++) & 0x000000FFL) << 8;
        type |= *(pos++) & 0x000000FFL;
        class = (*(pos++) & 0x000000FFL) << 8;
        class |= *(pos++) & 0x000000FFL;
        ttl = (*(pos++) & 0x000000FFL) << 8;
        ttl |= *(pos++) & 0x000000FFL;
        rdlength = (*(pos++) & 0x000000FFL) << 8;
        rdlength |= *(pos++) & 0x000000FFL;
        logMessage("    ->name: %s", namebuf);
        logMessage("    ->type: %x", type);
        logMessage("    ->class: %x", class);
        logMessage("    ->ttl: %d", ttl);
        logMessage("    ->rdlength: %d", rdlength);
        strcpy(rd, "    ->rd:");
        for (int i = 0; i < rdlength; ++i)
        {
            rd += strlen(rd);
            sprintf(rd, " %x", *(pos++));
        }
        logMessage("%s", namebuf);
    }
}