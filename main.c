/**
 * @see http://www.ietf.org/rfc/rfc1035.txt
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#include <time.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include "dns.h"
#include "record.h"

#define MSZ_NS          16
#define ENABLE_HOSTS    0

typedef char ns_ip[16];

static ns_ip dns_servers[MSZ_NS];
static int n_dns_servers;
static unsigned char * buf;
static int bufSize;

static char * strtokr(char *, const char *, char **);
void resolveHostname(unsigned char*, const int, const int);
void encodeHostname(unsigned char*, unsigned char*);
unsigned char* decodeHostname(unsigned char*, unsigned char*, int*);
int loadConf();
int bufsize(int, void *);

static int
sendDNSRequest(int query_mode, int len, const char * dns_server)
{
    socklen_t addrlen;
    unsigned short prefix;
    int sock;
    struct sockaddr_in dest;

    addrlen = sizeof (struct sockaddr_in);
    sock = 0;
    bzero(&dest, sizeof (dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(dns_server);
    switch (query_mode)
    {
        case IPPROTO_UDP:
        {
            sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            printf("Sending request...");
            if (sendto(sock, (char*) buf, len, 0,
                    (struct sockaddr*) &dest, addrlen) < 0)
            {
                printf("   failed\r\n");
                free(buf);
                buf = NULL;
                close(sock);
                sock = 0;
                return -1;
            }
            printf("   done\r\nReceiving response...");
            bzero(buf, bufSize);
            if (recvfrom(sock, (char*) buf, bufSize, 0,
                    (struct sockaddr*) &dest, (socklen_t*) & addrlen) < 0)
            {
                printf("failed\r\n");
                free(buf);
                buf = NULL;
                close(sock);
                sock = 0;
                return -1;
            }
            printf("done\r\n");
            break;
        }
        case IPPROTO_TCP:
        {
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            printf("Connect...");
            if (connect(sock, (const struct sockaddr *) &dest, addrlen) < 0)
            {
                printf("           failed\r\n");
                free(buf);
                buf = NULL;
                close(sock);
                sock = 0;
                return -1;
            }
            printf("           done\r\nSending request...");
            prefix = htons(len & 0xffffu);
            if (send(sock, &prefix, sizeof (unsigned short), 0) < 0
                    || send(sock, buf, len, 0) < 0)
            {
                printf("   failed\r\n");
                free(buf);
                buf = NULL;
                close(sock);
                sock = 0;
                return -1;
            }
            printf("   done [0x%i]\r\nReceiving response...", len);
            prefix = 0;
            if (recv(sock, &prefix, sizeof (unsigned short), 0) < 0)
            {
                printf("failed\r\n");
                free(buf);
                buf = NULL;
                close(sock);
                sock = 0;
                return -1;
            }
            prefix = ntohs(prefix);
            bzero(buf, prefix + 1);
            if (recv(sock, buf, prefix, 0) < 0)
            {
                printf("failed\r\n");
                free(buf);
                buf = NULL;
                close(sock);
                sock = 0;
                return -1;
            }
            printf("done [0x%x].\r\n", prefix);
            break;
        }
        default:
            free(buf);
            buf = NULL;
            return -1;
    }
    close(sock);
    sock = 0;
    return 0;
}

struct DNS_HEADER
{
    unsigned short id;

    unsigned char rd : 1;
    unsigned char tc : 1;
    unsigned char aa : 1;
    unsigned char opcode : 4;
    unsigned char qr : 1;

    unsigned char rcode : 4;
    unsigned char z : 3;
    unsigned char ra : 1;

    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

#pragma pack(push, 1)

struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;

static void
handle_Interruption(int param)
{
    printf("I'm dead thanks to [%i]!\r\n", param);
    if (buf != NULL)
    {
        free(buf);
        buf = (unsigned char *) NULL;
    }
    exit(SIGINT);
}

int
main(int argc, char *argv[])
{
    unsigned char hostname[256];

    loadConf();
    //*
    if (buf != NULL)
    {
        printf("There are already an running instance!\r\n");
        return -1;
    }
    buf = (unsigned char *) NULL;
    signal(SIGINT, handle_Interruption);

    bzero(hostname, 256);
    printf("Enter Hostname to Lookup : ");
    scanf("%s", hostname);

    //resolveHostname(hostname, T_A, IPPROTO_UDP);
    resolveHostname(hostname, T_A, IPPROTO_TCP);
    //*/
    return 0;
}

void
resolveHostname(unsigned char *host,
        const int query_type,
        const int query_mode)
{
    unsigned char *qname, *reader;
    int i, j, stop;
    int len;
    struct sockaddr_in a;
    struct RES_RECORD answers[20], auth[20], addit[20];
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;
    int ancount, nscount, arcount;

    printf("Allocating memory...\r\n");
    switch (query_mode)
    {
        case IPPROTO_UDP:
            bufSize = UDP_BUFFER_CAPACITY;
            break;
        case IPPROTO_TCP:
            bufSize = TCP_BUFFER_CAPACITY;
            break;
        default:
            return;
    }
    buf = (unsigned char *) malloc(bufSize);
    if (buf == NULL)
        return;
    bzero(buf, bufSize);

    printf("Resolving %s\r\n", host);

    {
        dns = (struct DNS_HEADER *) buf;
        dns->id = htons((unsigned short) (0xffffu & getpid()));
        dns->rd = 1;
        dns->qdcount = htons(1);
        len = sizeof (struct DNS_HEADER);
        qname = (unsigned char*) (buf + len);
        encodeHostname(qname, host);
        len += (strlen((const char *) qname) + sizeof (unsigned char));
        qinfo = (struct QUESTION*) (buf + len);
        qinfo->qtype = htons(query_type);
        qinfo->qclass = htons(1);
        len += sizeof (struct QUESTION);
    }

    sendDNSRequest(query_mode, len, dns_servers[0]);

    dns = (struct DNS_HEADER*) buf;

    printf("[AA    %i]\r\n"
            "[RA    %i]\r\n"
            "[TC    %i]\r\n",
            dns->aa, dns->ra, dns->tc);
    switch (dns->rcode)
    {
        case 0:
            printf("[RCODE 0] No error\r\n");
            break;
        case 1:
            printf("[RCODE 1] Format error\r\n");
            break;
        case 2:
            printf("[RCODE 2] Server failure\r\n");
            break;
        case 3:
            printf("[RCODE 3] Name Error (aa=%i)\r\n", dns->aa);
            break;
        case 4:
            printf("[RCODE 4] Not implemented\r\n");
            break;
        case 5:
            printf("[RCODE 5] Refused\r\n");
            break;
        default:
            printf("[RCODE %x] Unknown rcode\r\n", dns->rcode);
            break;
    }

    ancount = ntohs(dns->ancount);
    nscount = ntohs(dns->nscount);
    arcount = ntohs(dns->arcount);

    reader = buf + len;

    printf("\nThe response contains : ");
    printf("\n %d Questions.", ntohs(dns->qdcount));
    printf("\n %d Answers.", ancount);
    printf("\n %d Authoritative Servers.", nscount);
    printf("\n %d Additional records.\n\n", arcount);

    stop = 0;

    for (i = 0; i < ancount; i++)
    {
        answers[i].name = decodeHostname(reader, buf, &stop);
        reader = reader + stop;

        answers[i].resource = (struct R_DATA*) (reader);
        reader = reader + sizeof (struct R_DATA);

        if (ntohs(answers[i].resource->type) == T_A) //if its an ipv4 address
        {
            answers[i].rdata = (unsigned char*) malloc(ntohs(answers[i].resource->data_len));

            for (j = 0; j < ntohs(answers[i].resource->data_len); j++)
            {
                answers[i].rdata[j] = reader[j];
            }

            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata = decodeHostname(reader, buf, &stop);
            reader = reader + stop;
        }
    }

    for (i = 0; i < nscount; i++)
    {
        auth[i].name = decodeHostname(reader, buf, &stop);
        reader += stop;

        auth[i].resource = (struct R_DATA*) (reader);
        reader += sizeof (struct R_DATA);

        auth[i].rdata = decodeHostname(reader, buf, &stop);
        reader += stop;
    }

    for (i = 0; i < arcount; i++)
    {
        addit[i].name = decodeHostname(reader, buf, &stop);
        reader += stop;

        addit[i].resource = (struct R_DATA*) (reader);
        reader += sizeof (struct R_DATA);

        if (ntohs(addit[i].resource->type) == T_A)
        {
            addit[i].rdata = (unsigned char*)
                    malloc(ntohs(addit[i].resource->data_len));
            for (j = 0; j < ntohs(addit[i].resource->data_len); j++)
                addit[i].rdata[j] = reader[j];

            addit[i].rdata[ntohs(addit[i].resource->data_len)] = '\0';
            reader += ntohs(addit[i].resource->data_len);
        }
        else
        {
            addit[i].rdata = decodeHostname(reader, buf, &stop);
            reader += stop;
        }
    }

    printf("\nAnswer Records : %d \n", ancount);
    for (i = 0; i < ancount; i++)
    {
        printf("Name : %s ", answers[i].name);

        if (ntohs(answers[i].resource->type) == T_A)
        {
            long *p;
            p = (long*) answers[i].rdata;
            a.sin_addr.s_addr = (*p);
            printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        }

        if (ntohs(answers[i].resource->type) == T_CNAME)
        {
            printf("has alias name : %s", answers[i].rdata);
        }
        printf("{TTL=%i}", answers[i].resource->ttl);

        free(answers[i].name);
        answers[i].name = NULL;
        free(answers[i].rdata);
        answers[i].rdata = NULL;
        printf("\n");
    }

    printf("\nAuthoritive Records : %d \n", nscount);
    for (i = 0; i < nscount; i++)
    {

        printf("Name : %s ", auth[i].name);
        if (ntohs(auth[i].resource->type) == 2)
        {
            printf("has nameserver : %s", auth[i].rdata);
        }
        printf("{TTL=%i}", auth[i].resource->ttl);

        free(auth[i].name);
        auth[i].name = NULL;
        free(auth[i].rdata);
        auth[i].rdata = NULL;
        printf("\n");
    }

    printf("\nAdditional Records : %d \n", arcount);
    for (i = 0; i < arcount; i++)
    {
        printf("Name : %s ", addit[i].name);
        if (ntohs(addit[i].resource->type) == 1)
        {
            long *p;
            p = (long*) addit[i].rdata;
            a.sin_addr.s_addr = (*p);
            printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        }
        printf("{TTL=%i}", addit[i].resource->ttl);

        free(addit[i].name);
        addit[i].name = NULL;
        free(addit[i].rdata);
        addit[i].rdata = NULL;
        printf("\n\n");
    }

    printf("Releasing memory...\r\n");
    free(buf);
    buf = NULL;
}

unsigned char *
decodeHostname(unsigned char* reader, unsigned char* buffer, int* count)
{
    unsigned char *name;
    unsigned char flag;
    unsigned short offset;
    unsigned int i, j;

    i = 0;
    j = 0;
    *count = 1;
    name = (unsigned char*) malloc(256);
    if (name == NULL)
        return (unsigned char *) NULL;

    while (*reader != 0)
    {
        flag = *reader >> 6;
        //printf("Flag: %i\r\n", flag);
        if (flag == 3)
        {
            offset = (*reader)*256 + *(reader + 1) - 49152;
            //printf("    Offset: %i\r\n", offset);
            reader = buffer + offset;
            j = 1;
        }
        else if (flag == 0)
        {
            flag = *reader;
            //printf("    Len: %i\r\n", flag);
            memcpy(name + i, ++reader, flag);
            //printf("    String: %s\r\n", name + i);
            i += flag;
            name[i++] = '.';
            reader += flag;
            if (j == 0)
                *count += (1 + flag);
        }
        else
        {
            free(name);
            name = (unsigned char *) NULL;
            return name;
        }
    }

    if (j == 1)
        ++*count;

    name[i - 1] = '\0';
    reader = realloc(name, i);
    if (reader != NULL)
        name = reader;

    return name;
}

int
loadConf()
{
    FILE *file;
    char *line, *ip, *save, *name;
    int sz_line;

    ip = save = name = (char *) NULL;
    n_dns_servers = 0;
    if (n_dns_servers < MSZ_NS)
        strcpy(dns_servers[n_dns_servers++], "8.8.8.8\0");
    if (n_dns_servers < MSZ_NS)
        strcpy(dns_servers[n_dns_servers++], "208.67.222.222\0");
    if (n_dns_servers < MSZ_NS)
        strcpy(dns_servers[n_dns_servers++], "208.67.220.220\0");

    if ((file = fopen("/etc/resolv.conf", "r")) == NULL)
        return -1;

    sz_line = 128;
    line = (char *) malloc(sz_line);
    if (line == NULL)
    {
        fclose(file);
        return -2;
    }

    while (bzero(line, sz_line),
            fgets(line, sz_line, file) != NULL
            && n_dns_servers < MSZ_NS)
    {
        if (line[0] == '#')
            continue;
        if (strncmp(line, "nameserver", 10) == 0)
        {
            strtokr(line, " \r\n", &save);
            ip = strtokr(NULL, " \r\n", &save);
            printf("Load NS IP [%i]: %s\r\n", n_dns_servers, ip);
            strcpy(dns_servers[n_dns_servers++], ip);
        }
    }

    free(line);
    line = (char *) NULL;
    fclose(file);
#if ENABLE_HOSTS
    if ((file = fopen("/etc/hosts", "r")) == NULL)
        return -1;
    sz_line = 512;
    line = (char *) malloc(sz_line);
    if (line == NULL)
    {
        fclose(file);
        return -2;
    }

    printf("Reading /etc/hosts ...\r\n");
    // TODO
    while (bzero(line, sz_line),
            fgets(line, sz_line, file) != NULL)
    {
        if (line[0] == '#' || line[0] == '\r'
                || line[0] == '\n')
            break;
        printf("Parsing the line <%i>%s", strlen(line), line);
        ip = name = save = NULL;
        ip = strtokr(line, "\t\r\n", &save);
        name = strtokr(NULL, "\t\r\n", &save);
        if (!ip || !name)
            continue;
        printf("{Name:'%s',IP:'%s',Hash:'%x'}\r\n",
                name, ip, hashCode(strlen(name), name));
    }
    fclose(file);
    free(line);
    line = (char *) NULL;
#endif
    return 0;
}

void
encodeHostname(unsigned char* dns, unsigned char* host)
{
    char *dot;
    size_t len;

    dot = host;
    while (1)
    {
        dot = strchr(dot, '.');
        if (dot == NULL)
        {
            len = strlen(host);
            //printf("Dot not found[%i:%.*s].\r\n", len, len, host);
            *dns++ = (unsigned char) (len & 0xffu);
            memcpy(dns, host, len);
            break;
        }
        else
        {
            len = (int) dot - (int) host;
            //printf("Dot found    [%i:%.*s].\r\n", len, len, host);
            *dns++ = (unsigned char) (len & 0xffu);
            memcpy(dns, host++, len);
        }
        dns += len;
        host += len;
        dot = host;
    }
}

int
bufsize(int cap, void * buf)
{
    int i;
    uint64_t *l;
    uint32_t *m;
    uint16_t *n;
    uint8_t *o;

    for (i = cap; i != 0;)
    {
        i -= sizeof (uint64_t) / sizeof (char);
        //printf("Exam buffer @ %i...\r\n", i);
        if (i < 0)
        {
            i = 0;
        }
        l = (uint64_t *) (buf + i);
        if (*l != 0)
            break;
        //printf("Buffer @ %i is empty.\r\n", i);
    }

    if (*l == 0)
        return 0;

    m = &((uint32_t *) l)[1];
    if (*m != 0)
    {
        n = &((uint16_t *) m)[1];
        if (*n != 0)
        {
            o = &((uint8_t *) n)[1];
            if (*o != 0)
            {
                return (int) o - (int) buf + 1;
            }
            o = (uint8_t *) n;
            if (*o != 0)
            {
                return (int) o - (int) buf + 1;
            }
        }
        n = (uint16_t *) m;
        if (*n != 0)
        {
            o = &((uint8_t *) n)[1];
            if (*o != 0)
            {
                return (int) o - (int) buf + 1;
            }
            o = (uint8_t *) n;
            if (*o != 0)
            {
                return (int) o - (int) buf + 1;
            }
        }
    }
    m = (uint32_t *) l;
    if (*m != 0)
    {
        n = &((uint16_t *) m)[1];
        if (*n != 0)
        {
            o = &((uint8_t *) n)[1];
            if (*o != 0)
            {
                return (int) o - (int) buf + 1;
            }
            o = (uint8_t *) n;
            if (*o != 0)
            {
                return (int) o - (int) buf + 1;
            }
        }
        n = (uint16_t *) m;
        if (*n != 0)
        {
            o = &((uint8_t *) n)[1];
            if (*o != 0)
            {
                return (int) o - (int) buf + 1;
            }
            o = (uint8_t *) n;
            if (*o != 0)
            {
                return (int) o - (int) buf + 1;
            }
        }
    }

    return 0;
}

static char *
strtokr(char *s, const char *delim, char **save_ptr)
{
    char *token;

    if (s == NULL)
        s = *save_ptr;

    /* Scan leading delimiters.  */
    s += strspn(s, delim);
    if (*s == '\0')
        return NULL;

    /* Find the end of the token.  */
    token = s;
    s = strpbrk(token, delim);
    if (s == NULL)
        /* This token finishes the string.  */
        *save_ptr = strchr(token, '\0');
    else
    {
        /* Terminate the token and make *SAVE_PTR point past it.  */
        *s = '\0';
        *save_ptr = s + 1;
    }

    return token;
}