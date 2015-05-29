#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<unistd.h>

#define BUFFER_SIZE 65536

char dns_servers[16][128];
int dns_server_count = 0;

#define T_A 1
#define T_NS 2
#define T_CNAME 5
#define T_SOA 6
#define T_PTR 12
#define T_MX 15

void
resolveHostname(unsigned char *, int);
void
encodeHostname(unsigned char *, unsigned char *);
unsigned char*
decodeHostname(unsigned char *, unsigned char *, int *);
void
loadConf();

typedef struct
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

    unsigned short q_count;
    unsigned short ans_count;
    unsigned short auth_count;
    unsigned short add_count;
} dns_header;

typedef struct
{
    unsigned short qtype;
    unsigned short qclass;
} dns_query;

#pragma pack(push, 1)

typedef struct
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
} dns_res_data;
#pragma pack(pop)

typedef struct
{
    unsigned char *name;
    dns_res_data *resource;
    unsigned char *rdata;
} dns_res_record;

int
main(int argc, char *argv[])
{
    unsigned char hostname[100];
    
    loadConf();

    printf("Enter Hostname to Lookup : ");
    scanf("%s", hostname);

    resolveHostname(hostname, T_A);

    return 0;
}

void
resolveHostname(unsigned char *host, int query_type)
{
    unsigned char buf[BUFFER_SIZE], *qname, *reader;
    int i, j, stop, s;

    struct sockaddr_in a;

    dns_res_record answers[20], auth[20], addit[20];
    struct sockaddr_in dest;

    dns_header *dns = NULL;
    dns_query *qinfo = NULL;

    printf("Resolving %s", host);

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(dns_servers[0]);


    bzero(buf, BUFFER_SIZE);
    dns = (dns_header *) &buf;

    dns->id = htons((unsigned short) (0xffffu & getpid()));
    dns->rd = 1;
    dns->q_count = htons(1);


    qname = (unsigned char*) &buf[sizeof (dns_header)];

    encodeHostname(qname, host);
    qinfo = (dns_query*) &buf[sizeof (dns_header) + (strlen((const char*) qname) + 1)];

    qinfo->qtype = htons(query_type);
    qinfo->qclass = htons(1);

    printf("\nSending Packet...");
    if (sendto(s, (char*) buf, sizeof (dns_header) + (strlen((const char*) qname) + 1) + sizeof (dns_query), 0, (struct sockaddr*) &dest, sizeof (dest)) < 0)
    {
        perror("sendto failed");
        return;
    }
    printf("Done");


    i = sizeof dest;
    printf("\nReceiving answer...");
    if (recvfrom(s, (char*) buf, BUFFER_SIZE, 0, (struct sockaddr*) &dest, (socklen_t*) & i) < 0)
    {
        perror("recvfrom failed");
        return;
    }
    printf("Done");

    dns = (dns_header*) buf;


    reader = &buf[sizeof (dns_header) + (strlen((const char*) qname) + 1) + sizeof (dns_query)];

    printf("\nThe response contains : ");
    printf("\n %d Questions.", ntohs(dns->q_count));
    printf("\n %d Answers.", ntohs(dns->ans_count));
    printf("\n %d Authoritative Servers.", ntohs(dns->auth_count));
    printf("\n %d Additional records.\n\n", ntohs(dns->add_count));


    stop = 0;

    for (i = 0; i < ntohs(dns->ans_count); i++)
    {
        answers[i].name = decodeHostname(reader, buf, &stop);
        reader = reader + stop;

        answers[i].resource = (dns_res_data*) (reader);
        reader = reader + sizeof (dns_res_data);

        if (ntohs(answers[i].resource->type) == 1)
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


    for (i = 0; i < ntohs(dns->auth_count); i++)
    {
        auth[i].name = decodeHostname(reader, buf, &stop);
        reader += stop;

        auth[i].resource = (dns_res_data*) (reader);
        reader += sizeof (dns_res_data);

        auth[i].rdata = decodeHostname(reader, buf, &stop);
        reader += stop;
    }


    for (i = 0; i < ntohs(dns->add_count); i++)
    {
        addit[i].name = decodeHostname(reader, buf, &stop);
        reader += stop;

        addit[i].resource = (dns_res_data*) (reader);
        reader += sizeof (dns_res_data);

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


    printf("\nAnswer Records : %d \n", ntohs(dns->ans_count));
    for (i = 0; i < ntohs(dns->ans_count); i++)
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
        free(answers[i].rdata);
        printf("\n");
    }


    printf("\nAuthoritive Records : %d \n", ntohs(dns->auth_count));
    for (i = 0; i < ntohs(dns->auth_count); i++)
    {

        printf("Name : %s ", auth[i].name);
        if (ntohs(auth[i].resource->type) == 2)
        {
            printf("has nameserver : %s", auth[i].rdata);
        }
        free(auth[i].name);
        free(auth[i].rdata);
        printf("\n");
    }


    printf("\nAdditional Records : %d \n", ntohs(dns->add_count));
    for (i = 0; i < ntohs(dns->add_count); i++)
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
        free(addit[i].rdata);
        printf("\n");
    }


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
        if (flag == 3)
        {
            offset = (*reader)*256 + *(reader + 1) - 49152;
            reader = buffer + offset;
            j = 1;
        }
        else if (flag == 0)
        {
            flag = *reader;
            memcpy(name + i, ++reader, flag);
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
    int i, sz_line;

    i = 0;
    strcpy(dns_servers[i++], "8.8.8.8\0");
    strcpy(dns_servers[i++], "208.67.222.222\0");
    strcpy(dns_servers[i++], "208.67.220.220\0");

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
            fgets(line, sz_line, file) != NULL)
    {
        if (line[0] == '#')
            continue;
        if (strncmp(line, "nameserver", 10) == 0)
        {
            strtok_r(line, " ", &save);
            ip = strtok_r(NULL, " ", &save);
            strcpy(dns_servers[i++], ip);
        }
    }

    free(line);
    line = (char *) NULL;
    fclose(file);
}

void
encodeHostname(unsigned char* dns, unsigned char* host)
{
    int lock = 0, i;
    strcat((char*) host, ".");

    for (i = 0; i < strlen((char*) host); i++)
    {
        if (host[i] == '.')
        {
            *dns++ = i - lock;
            for (; lock < i; lock++)
            {
                *dns++ = host[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';
}