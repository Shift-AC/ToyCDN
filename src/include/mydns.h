#ifndef __MYDNS_H__
#define __MYDNS_H__

#include <netdb.h>
#include "types.h"

#define MAX_ATTEMPT 3
#define RTO_IN_US 1000000

struct dnshdr
{
    word id;
    word rcode :4;
    word z :3;
    word ra :1;
    word rd :1;
    word tc :1;
    word aa :1;
    word opcode :4;
    word qr :1;
    word qdcount;
    word ancount;
    word nscount;
    word arcount;
};

struct dns_question
{
    byte *qname;
    word qtype;
    word qclass;
};

struct dns_answer
{
    byte *name;
    word type;
    word class;
    word ttl;
    word rdlength;
    word *rdata;
};

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
int init_mydns(const char *dns_ip, unsigned int dns_port, const char *client_ip);


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
            const struct addrinfo *hints, struct addrinfo **res);

/**
 * Release the addrinfo structure.
 *
 * @param  p  the addrinfo structure to release
 *
 * @return 0 on success, -1 otherwise
 */
int mydns_freeaddrinfo(struct addrinfo *p);

char *atoqn(char *dest, const char *src);
char *qntoa(char *dest, const char *src);
void dumpDNSPacket(const void *pak, int len);

#endif