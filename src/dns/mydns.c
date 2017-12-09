#include "stdhdr.h"
#include "mydns.h"
#include "log.h"

static sockaddr_in dns_addr;
static sockaddr_in my_addr;
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
    byte buf[16];
    if (inet_aton(dns_ip, &dns_addr.sin_addr) == 0)
    {
        return -1;
    }
    dns_addr.sin_port = htons(dns_port);

    if (inet_aton(client_ip, &my_addr.sin_addr) == 0)
    {
        return -1;
    }
    my_addr.sin_port = 0;

    return 0;
}

/* make connection to dns server */
static int mydns_netdial()
{
    socklen_t len = sizeof(struct sockaddr_in);
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) 
    {
        goto netdial_fail_final;
    }

    if (bind(s, (struct sockaddr*)&my_addr, len) < 0)
    {
        goto netdial_fail_free;
    }

    if (connect(s, (struct sockaddr*)&dns_addr, len) < 0 && 
        errno != EINPROGRESS) 
    {
        goto netdial_fail_free;
    }

    return s;
netdial_fail_free:
    close(s);
netfail_fail_final:
    return -1;
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
    int sockfd;
    byte *pak = malloc(8192);
    int len;
    if ((len = generateRequest(node, service, pak)) == 0)
    {
        return -1;
    }

    if ((sockfd = mydns_netdial() == -1)
    {
        return -1;
    }



    free(pak);
    return -1;
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
    return -1;
}
