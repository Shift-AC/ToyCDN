#include "stdhdr.h"
#include "log.h"
#include "types.h"
#include "lock.h"
#include "mydns.h"

void printAddrList(struct addrinfo *ite)
{
    while (ite)
    {
        logMessage("IP address of %s: %s", ite->ai_canonname, 
            inet_ntoa(((struct sockaddr_in*)ite->ai_addr)->sin_addr));
        logVerbose("  ->port: %d", 
            ntohs(((struct sockaddr_in*)ite->ai_addr)->sin_port));
        logVerbose("  ->family: %d", ite->ai_addr->sa_family);
        logVerbose("  ->flags: %x", ite->ai_flags);
        logVerbose("  ->socktype: %d", ite->ai_socktype);
        ite = ite->ai_next;
    }
}

int main()
{
    char line[1024];
    
    verbose = 10;
    initLog();
    printInitLog();
    init_mydns("127.0.0.1", 23333, "127.0.0.1");

    while (fgets(line, 1024, stdin) != NULL)
    {
        struct addrinfo *res;
        line[strlen(line) - 1] = 0;
        if (line[0] == 0)
        {
            strcpy(line, "video.pku.edu.cn");
        }
        if (resolve(line, "80", NULL, &res) != -1)
        {
            printAddrList(res);
            mydns_freeaddrinfo(res);
        }
        else
        {
            logVerbose("Failed to resolve.");
        }
    }
}