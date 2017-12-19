#include "stdhdr.h"
#include "log.h"
#include "types.h"
#include "mydns.h"

char *usage = 
    "nameserver (-r) [log] [ip] [port] [servers] (LSAs)\n"
    "  -r:\n"
    "    Use Round-Robin load balancing.\n"
    "  log(required):\n"
    "    The file path to print required log, or '!' to print to stdout.\n"
    "  ip(required):\n"
    "    The IP address that this server listen on.\n"
    "  port(required):\n"
    "    The port number that this server listen on.\n"
    "  servers(required):\n"
    "    The file containing the IP addresses of the content servers.\n"
    "  LSAs(required when -r is not specified):\n"
    "    The file containing the LSA information.\n";
    
#define MAX_RETRY 20
#define MAX_HOST 128
#define MAX_LSABUF 1024
#define BUFSIZE 8192
#define MAX_NAME 128

static struct lsabuf_t
{
    unsigned int addr;
    unsigned int seq; 
    unsigned int nb[MAX_HOST];
    int nbCount;
}lsabuf[MAX_LSABUF];
static int lsaCount = 0;

static int port = 0;
static int connfd;
static struct sockaddr_in serverInfo, clientInfo;
static socklen_t len = sizeof(struct sockaddr_in);
static byte sendBuf[BUFSIZE];
static int sendLen;
static byte recvBuf[BUFSIZE];
static FILE *outputFile;
static unsigned int servers[MAX_HOST];
static int serverCount = 0;
static unsigned int hosts[MAX_HOST * MAX_HOST];
static int hostCount = 0;
static int map[MAX_HOST][MAX_HOST];
static int dist[MAX_HOST];
static int used[MAX_HOST];
static int useRR = 0;
static char rawNames[MAX_HOST][MAX_NAME];
static int rawNameCount;

static int compareServer(const void *a, const void *b)
{
    return *(const unsigned int*)a - *(const unsigned int*)b;
}

static int compareLSABuf(const void *ta, const void *tb)
{
    const struct lsabuf_t *a = ta;
    const struct lsabuf_t *b = tb;
    return a->addr == b->addr ? b->seq - a->seq : a->addr - b->addr;
}

static void initServers(const char *path)
{
    FILE *is = fopen(path, "r");
    char line[BUFSIZE];
    int lc = 1;

    if (is == NULL)
    {
        logError("Can't open server IP file %s!", line);
        failExit("fopen");
    }

    while (fgets(line, BUFSIZE, is) != NULL)
    {
        line[strlen(line) - 1] = 0;
        if (inet_aton(line, (struct in_addr*)&servers[serverCount++]) == 0)
        {
            logFatal("Syntax error in server IP file %s line %d(%s)!",
                path, lc, line);
        }
        logVerbose("Server #%d: %s", lc, line);
        ++lc;
    }

    fclose(is);
}

static int binarySearch(const unsigned int *arr, int len, unsigned int tgt)
{
    int s = 0; 
    int e = len;

    while (s + 1 < e)
    {
        int mid = (s + e) >> 1;
        if (arr[mid] < tgt)
        {
            s = mid + 1;
        }
        else if (arr[mid] > tgt)
        {
            e = mid;
        }
        else
        {
            return mid;
        }
    }

    return arr[s] == tgt ? s : -1;
}

static int find(const char *str, const char c)
{
    const char *st = str;
    do
    {
        if (c == *str)
        {
            return str - st;
        }
    }
    while (*(str++));

    return -1;
}

static int ston(const char *name, struct in_addr* paddr)
{
    char ipbuf[64];
    int ret = inet_aton(name, paddr);
    if (ret == 0)
    {
        logVerboseL(3, "Invalid IP address, mapping it to 233.233.233.*");
        int ind = 0;
        for (ind = 0; ind < rawNameCount; ++ind)
        {
            if (!strcmp(name, rawNames[ind]))
            {
                sprintf(ipbuf, "233.233.233.%d", ind);
                logVerboseL(3, "Found previous record on %s.", ipbuf);
                return inet_aton(ipbuf, paddr);
            }
        }
        strcpy(rawNames[rawNameCount], name);
        sprintf(ipbuf, "233.233.233.%d", rawNameCount++);
        logVerboseL(3, "Create new record on %s.", ipbuf);
        return inet_aton(ipbuf, paddr);        
    }
    return ret;
}

static char* parseLSALine(
    char *line, struct lsabuf_t *buf, int ln, const char *path)
{
    int pos = find(line, ' ');
    int lpos;
    char *inf;

    line[strlen(line) - 1] = 0;

    logVerbose("Parsing LSA line #%d: %s", ln, line);

    if (pos == -1)
    {
        logFatal("Syntax error in LSA file %s line %d(Space needed)!", 
            path, ln);
    }
    line[pos] = 0;

    if (ston(line, (struct in_addr*)&buf->addr) == 0)
    {
        logFatal("Syntax error in LSA file %s line %d(Invalid source IP)!", 
            path, ln);
    }
    logVerbose("  LSA source #%d: %s", ln, line);

    lpos = pos + 1;
    if ((pos = find(line + lpos, ' ')) == -1)
    {
        logFatal("Syntax error in LSA file %s line %d(Space needed)!", 
            path, ln);
    }
    line[lpos + pos] = 0;
    buf->seq = atoi(line + lpos);
    logVerbose("    ->seq: %d", buf->seq);

    inf = line + lpos + pos + 1;
    buf->nbCount = 0;
    while (*inf)
    {
        int pos = find(inf, ',');
        if (pos != -1)
        {
            inf[pos] = 0;	
        }
        if (ston(inf, (struct in_addr*)&(buf->nb[buf->nbCount++])) 
            == 0)
        {
            logFatal(
                "Syntax error in LSA file %s line %d(Invalid neighbor IP)!", 
                path, ln);
        }
        logVerbose("    ->nb[%d]: %s(%s)", buf->nbCount, inf,
            inet_ntoa(*(struct in_addr*)&(buf->nb[buf->nbCount - 1])));
        if (pos == -1)
        {
            break;
        }
        inf += pos + 1;
    }

    return line + lpos + pos + 1;
}

static void initHosts()
{
    int i;
    int j;
    qsort(lsabuf, lsaCount, sizeof(struct lsabuf_t), compareLSABuf);

    for (i = 0; i < lsaCount; ++i)
    {
        if (!i || lsabuf[i].addr != lsabuf[i - 1].addr)
        {
            logVerboseL(2, "Using latest LSA information(%d) of %s", 
                lsabuf[i].seq, inet_ntoa(*(struct in_addr*)&lsabuf[i].addr));
            hosts[hostCount++] = lsabuf[i].addr;
            for (j = 0; j < lsabuf[i].nbCount; ++j)
            {
                logVerboseL(2, "  ->neighbor[%d]: %s", j,
                    inet_ntoa(*(struct in_addr*)&lsabuf[i].nb[j]));
                hosts[hostCount++] = lsabuf[i].nb[j];
            }
        }
    }
    qsort(hosts, hostCount, sizeof(unsigned int), compareServer);
    
    int pos = 0;
    for (i = 1; i < hostCount; ++i)
    {
        if (hosts[i] != hosts[i - 1])
        {
            logVerbose("host[%d]: %s", pos, 
                inet_ntoa(*(struct in_addr*)&hosts[i]));
            hosts[++pos] = hosts[i];
        }
    }
    hostCount = pos + 1;

    for (i = 0; i < serverCount; ++i)
    {
        struct in_addr sv = *(struct in_addr*)&servers[i];
        servers[i] = binarySearch(hosts, hostCount, servers[i]);
        if (servers[i] == (unsigned int)-1)
        {
            logWarning("Server %d(%s) not found in network topology!", i,
                inet_ntoa(sv));
        }
        else
        {
            logVerbose("server[%d](%s) at %d", i, inet_ntoa(sv), servers[i]);
        }
    }
    logVerbose("Dump mapping information:");
    for (i = 0; i < rawNameCount; ++i)
    {
        logVerbose("  ->%s: 233.233.233.%d", rawNames[i], i);
    }
}

static void initLSA(const char *path)
{
    FILE *is = fopen(path, "r");
    char line[BUFSIZE];
    int ln = 1;
    int i;
    int j;

    if (is == NULL)
    {
        logError("Can't open server IP file %s!", line);
        failExit("fopen");
    }

    while (fgets(line, BUFSIZE, is) != NULL)
    {
        parseLSALine(line, lsabuf + lsaCount++, ln++, path);
    }

    initHosts();

    for (i = 0; i < lsaCount; ++i)
    {
        if (!i || lsabuf[i].addr != lsabuf[i - 1].addr)
        {
            unsigned int addr = lsabuf[i].addr;
            int pos = binarySearch(hosts, hostCount, addr);
            for (j = 0; j < lsabuf[i].nbCount; ++j)
            {
                int ipos = binarySearch(hosts, hostCount, 
                    lsabuf[i].nb[j]);
                map[pos][ipos] = 1;
                map[ipos][pos] = 1;
            }
        }
    }

    fclose(is);
}

static void dijkstra(unsigned int addr)
{
    int src = binarySearch(hosts, hostCount, addr);
    int i;
    int j;
    memset(dist, -1, sizeof(dist));
    memset(used, 0, sizeof(used));

    dist[src] = 0;

    for (i = 0; i < hostCount; ++i)
    {
        int tsrc = -1;
        int tdist = 2147483647;
        for (j = 0; j < hostCount; ++j)
        {
            if (used[j])
            {
                continue;
            }
            if (dist[j] != -1 && dist[j] < tdist)
            {
                tsrc = j;
                tdist = dist[j];
                break;
            }
        }
        if (tsrc == -1)
        {
            break;
        }

        used[tsrc] = 1;
        for (j = 0; j < hostCount; ++j)
        {
            if (map[tsrc][j] && (dist[j] == -1 || dist[j] > dist[tsrc] + 1))
            {
                dist[j] = dist[tsrc] + 1;
            }
        }
    }
}

static void parseArguments(int argc, char **argv)
{
    int apos = 0;
    argc = argc + 1 - 1;

    if (!strcmp(argv[++apos], "-r"))
    {
        useRR = 1;
    }
    else
    {
        --apos;
    }

    if (strcmp(argv[++apos], "!"))
    {
        outputFile = fopen(argv[apos], "r");
    }
    else
    {
        outputFile = stdout;
    }

    if (inet_aton(argv[++apos], &serverInfo.sin_addr) == 0)
    {
        logFatal("Invalid serverIP %s", argv[apos]);
    }
    //serverInfo.sin_addr.s_addr = htonl(INADDR_ANY);
    serverInfo.sin_family = AF_INET;
    port = atoi(argv[++apos]);
    serverInfo.sin_port = htons(port);

    initServers(argv[++apos]);

    if (!useRR)
    {
        initLSA(argv[++apos]);
    }
}

static unsigned int roundRobin()
{
    static int pos = 0;

    pos = pos == serverCount ? 0 :pos;

    return servers[pos++];
}

static unsigned int locationAware()
{
    static int pos = 0;
    unsigned int client = *(unsigned int*)&clientInfo.sin_addr;
    int ci;
    int mi;
    int i;
    if ((ci = binarySearch(hosts, hostCount, client)) == -1)
    {
        logWarning("Client not in the network!");
        
        pos = pos == hostCount ? 0 : pos;
        ci = hosts[pos++];
        logVerbose("Choose a client IP(%d, %s) using round-robin...", 
            pos - 1, inet_ntoa(*(struct in_addr*)&ci));
    }

    dijkstra(ci);
    logVerboseL(2, "Dump mapping information:");
    for (i = 0; i < rawNameCount; ++i)
    {
        logVerboseL(2, "  ->%s: 233.233.233.%d", rawNames[i], i);
    }
    logVerboseL(2, "Dump distance information:");
    for (i = 0; i < hostCount; ++i)
    {
        logVerboseL(2, "  ->%d(%s): %d", i, 
            inet_ntoa(*(struct in_addr*)&hosts[i]), dist[i]);
    }

    mi = 0;
    for (i = 1; i < serverCount; ++i)
    {
        if (dist[servers[i]] == -1)
        {
            continue;
        }
        if (dist[servers[mi]] == -1 || 
            dist[servers[i]] < dist[servers[mi]])
        {
            mi = i;
        }
    }
    return hosts[servers[mi]];

}

static inline unsigned int chooseServer()
{
    unsigned int ret;
    if (useRR)
    {
        ret = roundRobin();
    }
    else
    {
        ret = locationAware();
    }
    logMessage("Server %s chosen.", inet_ntoa(*(struct in_addr*)&ret));
    return ret;
}

static void parseRequest()
{
    struct dnshdr *shdr = (struct dnshdr*)sendBuf;
    char *ans;
    char buf[BUFSIZE];
    int qtype;
    int qclass;

    memcpy(sendBuf, recvBuf, BUFSIZE);
    ans = (char*)qntoa(buf, (const char*)(sendBuf + sizeof(struct dnshdr)));
    qtype = *(ans++) << 8;
    qtype |= *(ans++);
    qclass = *(ans++) << 8;
    qclass |= *(ans++);
    
    shdr->aa = 1;
    shdr->qr = 1;
    shdr->tc = 0;
    shdr->ra = 0;

    if (strcmp(buf, "video.pku.edu.cn") || qclass != 1 || qtype != 1)
    {
        shdr->rcode = 3;
        shdr->ancount = 0;
        sendLen = ans - (char*)sendBuf;
    }
    else
    {
        unsigned int server = chooseServer();
        struct timeval now;
        shdr->rcode = 0;
        shdr->ancount = 1;
        ans = atoqn(ans, "video.pku.edu.cn");
        // type
        *(ans++) = 0;
        *(ans++) = 1;
        // class
        *(ans++) = 0;
        *(ans++) = 1;
        //ttl
        *(ans++) = 0;
        *(ans++) = 0;
        // rdlen
        *(ans++) = 0;
        *(ans++) = 4;
        // rdata
        *(ans++) = server >> 24;
        *(ans++) = server >> 16;
        *(ans++) = server >> 8;
        *(ans++) = server;

        sendLen = ans - (char*)sendBuf;

        gettimeofday(&now, NULL);
        fprintf(outputFile, "%ld %s %s %s\n", now.tv_sec, 
            inet_ntoa(clientInfo.sin_addr),
            buf, inet_ntoa(serverInfo.sin_addr));
    }
}

static void initConnection()
{
    char errbuf[256];
    int attempt = 1;

    memset(&clientInfo, 0, sizeof(clientInfo));
    close(connfd);

    for (; attempt <= MAX_RETRY; ++attempt)
    {
        if ((connfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        {
            logError("Attempt #%d failed(%s): Can't create socket!", attempt,
                strerrorV(errno, errbuf));
            continue;
        }

        if (bind(connfd, (struct sockaddr*)&serverInfo, len) == -1)
        {
            logError("Attempt %d failed(%s): Can't bind to port!", attempt,
                strerrorV(errno, errbuf));
            continue;
        }

        logMessage("Listening on port %d...", port);
        break;
    }

    if (attempt > MAX_RETRY)
    {
        logFatal("%d fails in initConnection, exit.", attempt);
    }
}

int main(int argc, char **argv)
{
    int reinit = 1;
    char errbuf[256];

    if (argc < 6)
    {
        printUsageAndExit(argv);
    }

    verbose = 2;
    initLog();
    printInitLog();

    parseArguments(argc, argv);

    while (1)
    {
        int recvLen;
        if (reinit)
        {
            initConnection();
            reinit = 0;
        }
        
        if ((recvLen = recvfrom(connfd, recvBuf, BUFSIZE, 0, 
            (struct sockaddr*)&clientInfo, &len)) == -1)
        {
            logError("Socket broken when receiving(%s), trying to restart...",
                strerrorV(errno, errbuf));
            reinit = 1;
            continue;
        }
        logMessage("Packet received from %s:%d",
            inet_ntoa(clientInfo.sin_addr), (int)clientInfo.sin_port);
        dumpDNSPacket(recvBuf, recvLen);

        parseRequest();

        if (sendto(connfd, sendBuf, sendLen, 0, 
            (struct sockaddr *)&clientInfo, len) == -1)
        {
            logError("Socket broken when sending(%s), trying to restart...",
                strerrorV(errno, errbuf));
            reinit = 1;
            continue;
        }

        logMessage("Packet sent to %s:%d",
            inet_ntoa(clientInfo.sin_addr), (int)clientInfo.sin_port);
        dumpDNSPacket(sendBuf, sendLen);
    }

    close(connfd);
    return 0;
}
