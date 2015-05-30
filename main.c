/**
 * @see http://www.ietf.org/rfc/rfc1035.txt
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#define BUFFER_SIZE 65536
#define MSZ_NS      16

typedef char ns_ip[16];

static ns_ip dns_servers[MSZ_NS];
static int n_dns_servers;
static unsigned char * buf;


#define T_A 1
#define T_NS 2
#define T_CNAME 5
#define T_SOA 6
#define T_PTR 12
#define T_MX 15

void resolveHostname(unsigned char*, const int, const int);
void encodeHostname(unsigned char*, unsigned char*);
unsigned char* decodeHostname(unsigned char*, unsigned char*, int*);
void
loadConf();

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

    if (buf != NULL)
    {
        printf("There are already an running instance!\r\n");
        return -1;
    }
    buf = (unsigned char *) NULL;
    signal(SIGINT, handle_Interruption);

    printf("Enter Hostname to Lookup : ");
    scanf("%s", hostname);

    resolveHostname(hostname, T_A, IPPROTO_UDP);

    return 0;
}

void
resolveHostname(unsigned char *host,
        const int query_type,
        const int query_mode)
{
    socklen_t addrlen;

    unsigned char *qname, *reader;
    int i, j, stop, sock;
    int len;
    unsigned short prefix;
    struct sockaddr_in a;
    struct RES_RECORD answers[20], auth[20], addit[20];
    struct sockaddr_in dest;
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;
    int ancount, nscount, arcount;

    printf("Allocating memory...\r\n");
    buf = (unsigned char *) malloc(BUFFER_SIZE);
    if (buf == NULL)
        return;
    bzero(buf, BUFFER_SIZE);

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

    addrlen = sizeof (struct sockaddr_in);
    sock = 0;
    bzero(&dest, sizeof (dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    i = 0;
    dest.sin_addr.s_addr = inet_addr(dns_servers[i]);
    switch (query_mode)
    {
        case IPPROTO_UDP:
        {
            sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            printf("Sending request...");
            if (sendto(sock, (char*) buf, len, 0,
                    (struct sockaddr*) &dest, addrlen) < 0)
            {
                printf("failed\r\n");
                free(buf);
                buf = NULL;
                close(sock);
                sock = 0;
                return;
            }
            printf("done\r\nReceiving response...");
            if (recvfrom(sock, (char*) buf, BUFFER_SIZE, 0,
                    (struct sockaddr*) &dest, (socklen_t*) & addrlen) < 0)
            {
                printf("failed\r\n");
                free(buf);
                buf = NULL;
                close(sock);
                sock = 0;
                return;
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
                printf("failed\r\n");
                free(buf);
                buf = NULL;
                close(sock);
                sock = 0;
                return;
            }
            printf("done\r\nSending request...");
            prefix = htons(len & 0xffffu);
            if (send(sock, &prefix, sizeof (unsigned short), 0) < 0
                    || send(sock, buf, len, 0) < 0)
            {
                printf("failed\r\n");
                free(buf);
                buf = NULL;
                close(sock);
                sock = 0;
                return;
            }
            printf("done\r\nReceiving response...");
            prefix = 0;
            if (recv(sock, &prefix, sizeof (unsigned short), 0) < 0
                    || recv(sock, buf, BUFFER_SIZE, 0) < 0)
            {
                printf("failed\r\n");
                free(buf);
                buf = NULL;
                close(sock);
                sock = 0;
                return;
            }
            printf("done\r\n");
            prefix = ntohs(prefix);
            break;
        }
        default:
            free(buf);
            buf = NULL;
            return;
    }
    close(sock);
    sock = 0;

    dns = (struct DNS_HEADER*) buf;

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

        if (ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
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

        if (ntohs(addit[i].resource->type) == 1)
        {
            addit[i].rdata = (unsigned char*) malloc(ntohs(addit[i].resource->data_len));
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

        if (ntohs(answers[i].resource->type) == 5)
        {
            printf("has alias name : %s", answers[i].rdata);
        }

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
        free(addit[i].name);
        addit[i].name = NULL;
        free(addit[i].rdata);
        addit[i].rdata = NULL;
        printf("\n");
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

    return name;
}

void
loadConf()
{
    FILE *file;
    char *line, *ip, *save;
    int sz_line;

    n_dns_servers = 0;
    if (n_dns_servers < MSZ_NS)
        strcpy(dns_servers[n_dns_servers++], "8.8.8.8\0");
    if (n_dns_servers < MSZ_NS)
        strcpy(dns_servers[n_dns_servers++], "208.67.222.222\0");
    if (n_dns_servers < MSZ_NS)
        strcpy(dns_servers[n_dns_servers++], "208.67.220.220\0");

    if ((file = fopen("/etc/resolv.conf", "r")) == NULL)
        return;

    sz_line = 128;
    line = (char *) malloc(sz_line);
    if (line == NULL)
    {
        fclose(file);
        return;
    }

    while (bzero(line, sz_line),
            fgets(line, sz_line, file) != NULL
            && n_dns_servers < MSZ_NS)
    {
        if (line[0] == '#')
            continue;
        if (strncmp(line, "nameserver", 10) == 0)
        {
            strtok_r(line, " ", &save);
            ip = strtok_r(NULL, " ", &save);
            printf("Load NS IP [%i]: %s\r\n", n_dns_servers, ip);
            strcpy(dns_servers[n_dns_servers++], ip);
        }
    }

    free(line);
    line = (char *) NULL;
    fclose(file);
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