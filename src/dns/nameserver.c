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

static struct lsabuf_t
{
	unsigned int addr;
	unsigned int seq; 
	unsigned int neighbor[MAX_HOST];
	int neighborCount;
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

static char* parseLSALine(
	char *line, struct lsabuf_t *buf, int ln, const char *path)
{
	int pos = find(line, ' ');
	int lpos;
	char *inf;

	if (pos == -1)
	{
		logFatal("Syntax error in LSA file %s line %d(Space needed)!", 
			path, ln);
	}
	line[pos] = 0;

	if (inet_aton(line, (struct in_addr*)&buf->addr) == 0)
	{
		logFatal("Syntax error in LSA file %s line %d(Invalid source IP)!", 
			path, ln);
	}
        logVerbose("LSA source #%d; %s", ln, line);

	lpos = pos + 1;
	if ((pos = find(line + lpos, ' ')) == -1)
	{
		logFatal("Syntax error in LSA file %s line %d(Space needed)!", 
			path, ln);
	}
	line[lpos + pos] = 0;
	buf->seq = atoi(line + lpos);
        logVerbose("  ->seq: %d", buf->seq);

	inf = line + lpos + pos + 1;
	buf->neighborCount = 0;
	while (*inf)
	{
		int pos = find(inf, ',');
		if (pos != -1)
		{
			inf[pos] = 0;	
		}
		if (inet_aton(inf, 
			(struct in_addr*)&(buf->neighbor[buf->neighborCount++])) == 0)
		{
			logFatal(
				"Syntax error in LSA file %s line %d(Invalid neighbor IP)!", 
				path, ln);
		}
                logVerbose("  ->neighbor[%d]: %s", buf->neighborCount, inf);
		inf += pos + 1;
	}

	return line + lpos + pos + 1;
}

static void initHosts()
{
	qsort(lsabuf, lsaCount, sizeof(struct lsabuf_t), compareLSABuf);

	for (int i = 0; i < lsaCount; ++i)
	{
		if (!i || lsabuf[i].addr != lsabuf[i - 1].addr)
		{
			hosts[hostCount++] = lsabuf[i].addr;
			for (int j = 0; j < lsabuf[i].neighborCount; ++j)
			{
				hosts[hostCount++] = lsabuf[i].neighbor[j];
			}
		}
	}
	qsort(hosts, hostCount, sizeof(unsigned int), compareServer);
	
	int pos = 0;
	for (int i = 1; i < hostCount; ++i)
	{
		if (hosts[i] != hosts[i - 1])
		{
                        logVerbose("host[%d]: %s", pos, 
                            inet_ntoa(*(struct in_addr*)&hosts[i]));
			hosts[++pos] = hosts[i];
		}
	}
	hostCount = pos + 1;

	for (int i = 0; i < serverCount; ++i)
	{
		servers[i] = binarySearch(hosts, hostCount, servers[i]);
	}
}

static void initLSA(const char *path)
{
	FILE *is = fopen(path, "r");
	char line[BUFSIZE];
	int ln = 1;

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

	for (int i = 0; i < lsaCount; ++i)
	{
		if (!i || lsabuf[i].addr != lsabuf[i - 1].addr)
		{
			unsigned int addr = lsabuf[i].addr;
			int pos = binarySearch(hosts, hostCount, addr);
			for (int j = 0; j < lsabuf[i].neighborCount; ++j)
			{
				int ipos = binarySearch(hosts, hostCount, 
					lsabuf[i].neighbor[j]);
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
	memset(dist, -1, sizeof(dist));
	memset(used, 0, sizeof(used));

	dist[src] = 0;

	for (int i = 0; i < hostCount; ++i)
	{
		int tsrc = -1;
		int tdist = 2147483647;
		for (int j = 0; j < hostCount; ++j)
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
		for (int j = 0; j < hostCount; ++j)
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
	argc = argc + 1 - 1;

    if (!strcmp(argv[1], "-r"))
	{
		useRR = 1;
	}

	if (strcmp(argv[2], "!"))
	{
		outputFile = fopen(argv[2], "r");
	}
	else
	{
		outputFile = stdout;
	}

	if (inet_aton(argv[3], &serverInfo.sin_addr) == 0)
	{
		logFatal("Invalid serverIP %s", argv[3]);
	}
	serverInfo.sin_addr.s_addr = htonl(INADDR_ANY);
	serverInfo.sin_family = AF_INET;
	port = atoi(argv[4]);
	serverInfo.sin_port = htons(port);

	initServers(argv[5]);

	if (!useRR)
	{
		initLSA(argv[6]);
	}
}

static unsigned int roundRobin()
{
	static int pos = 0;

	pos = pos == serverCount ? 0 :pos;

	return hosts[servers[pos++]];
}

static unsigned int locationAware()
{
	unsigned int client = *(unsigned int*)&clientInfo.sin_addr;
	int ci;
	int mi;
	if ((ci = binarySearch(hosts, hostCount, client)) == -1)
	{
		return roundRobin();
	}

	dijkstra(ci);
	
	mi = 0;
	for (int i = 1; i < serverCount; ++i)
	{
		if (dist[i] == -1)
		{
			continue;
		}
		if (dist[servers[mi]] == -1 || dist[i] < dist[servers[mi]])
		{
			mi = i;
		}
	}
	return hosts[servers[mi]];

}

static inline unsigned int chooseServer()
{
	if (useRR)
	{
		return roundRobin();
	}
	else
	{
		return locationAware();
	}
}

static void parseRequest()
{
	struct dnshdr *shdr = (struct dnshdr*)sendBuf;
	char *ans;
	char buf[BUFSIZE];
	int qtype;
	int qclass;

	memcpy(sendBuf, recvBuf, BUFSIZE);
	qntoa(buf, (const char*)(recvBuf + sizeof(struct dnshdr)));
	ans = (char*)sendBuf + sizeof(struct dnshdr) + strlen(buf) + 1;
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
	}
	else
	{
		unsigned int server = chooseServer();
		struct timeval now;
		shdr->rcode = 0;
		shdr->ancount = 1;
		ans = qntoa(ans, "video.pku.edu.cn");
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

		sendLen = (ans - (char*)sendBuf) + 1;

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
	memset(&serverInfo, 0, sizeof(serverInfo));
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

    verbose = 10;
    initLog();

    parseArguments(argc, argv);
    printInitLog();

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
		dumpDNSPacket(recvBuf, recvLen);

		logMessage("Packet received from %s:%d",
			inet_ntoa(clientInfo.sin_addr), (int)clientInfo.sin_port);

        parseRequest();

		dumpDNSPacket(sendBuf, sendLen);
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
	}

	close(connfd);
	return 0;
}
