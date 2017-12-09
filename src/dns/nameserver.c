#include "stdhdr.h"
#include "log.h"
#include "types.h"

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
    
#define MAX_ATTEMPT 20
#define BUFSIZE 8192

static int port = 0;
static char *path;
static int connfd;
static struct sockaddr_in serverInfo, clientInfo;
static socklen_t len = sizeof(struct sockaddr_in);
static byte sendBuf[BUFSIZE];
static byte recvBuf[BUFSIZE];
static FILE *outputFile;
static char **servers;

static void parseArguments(int argc, char **argv)
{
    
}

static void parseRequest()
{

}

static void initConnection()
{
	char errbuf[256];
	int attempt = 1;

	memset(&clientInfo, 0, sizeof(clientInfo));
	memset(&serverInfo, 0, sizeof(serverInfo));
	close(connfd);

	for (; attempt <= MAX_ATTEMPT; ++attempt)
	{
		if ((connfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		{
			logError("Attempt #%d failed(%s): Can't create socket!", attempt,
				strerrorV(errno, errbuf));
			continue;
		}
/*
		serverInfo.sin_family = AF_INET;
		serverInfo.sin_port = htons(port);
		serverInfo.sin_addr.s_addr = htonl(INADDR_ANY);
*/
		if (bind(connfd ,(struct sockaddr*)&serverInfo, len) == -1)
		{
			logError("Attempt %d failed(%s): Can't bind to port!", attempt,
				strerrorV(errno, errbuf));
			continue;
		}

		logMessage("Listening on port %d...", port);
		break;
	}

	if (attempt > MAX_ATTEMPT)
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

    initLog();

    parseArguments(argc, argv);
    printInitLog();

	while (1)
	{
		long x;	
		
		if (reinit)
		{
			initConnection();
			reinit = 0;
		}
		
		if (recvfrom(connfd, recvBuf, BUFSIZE, 0, 
			(struct sockaddr*)&clientInfo, &len) == -1)
		{
			logError("Socket broken when receiving(%s), trying to restart...",
				strerrorV(errno, errbuf));
			reinit = 1;
			continue;
		}

		logMessage("Packet received from %s:%d",
			inet_ntoa(clientInfo.sin_addr), (int)clientInfo.sin_port);

        parseRequest();

		if (sendto(connfd, sendBuf, BUFSIZE, 0, 
			(struct sockaddr *)&clientInfo, len) == -1)
		{
			logError("Socket broken when sending(%s), trying to restart...",
				strerrorV(errno, errbuf));
			reinit = 1;
			continue;
		}

		logMessage("Packet #%ld sent to %s:%d(total %ld)", x,
			inet_ntoa(clientInfo.sin_addr), (int)clientInfo.sin_port, ++sent);
	}

	close(connfd);
	return 0;
}
