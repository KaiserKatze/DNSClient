
//DNS Query Program on Linux
//Author : Silver Moon (m00n.silv3r@gmail.com)
//Dated : 29/4/2009

//Header Files
#include<stdio.h>	//printf
#include<string.h>	//strlen
#include<stdlib.h>	//malloc
#include<sys/socket.h>	//you know what this is for
#include<arpa/inet.h>	//inet_addr , inet_ntoa , ntohs etc
#include<netinet/in.h>
#include<unistd.h>	//getpid

#define BUFFER_SIZE 65536
//List of DNS Servers registered on the system
char dns_servers[16][128];
int dns_server_count = 0;
//Types of DNS resource records :)

#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server

//Function Prototypes
void resolveHostname(unsigned char*, int);
void encodeHostname(unsigned char*, unsigned char*);
unsigned char* decodeHostname(unsigned char*, unsigned char*, int*);
void
loadConf();

//DNS header structure

struct DNS_HEADER
{
    unsigned short id; // identification number

    unsigned char rd : 1; // recursion desired
    unsigned char tc : 1; // truncated message
    unsigned char aa : 1; // authoritive answer
    unsigned char opcode : 4; // purpose of message
    unsigned char qr : 1; // query/response flag

    unsigned char rcode : 4; // response code
    unsigned char cd : 1; // checking disabled
    unsigned char ad : 1; // authenticated data
    unsigned char z : 1; // its z! reserved
    unsigned char ra : 1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure

struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)

struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

//Pointers to resource record contents

struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

//Structure of a Query

typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;

int
main(int argc, char *argv[])
{
    unsigned char hostname[256];

    //Get the DNS servers from the resolv.conf file
    loadConf();

    //Get the hostname from the terminal
    printf("Enter Hostname to Lookup : ");
    scanf("%s", hostname);

    //Now get the ip of this hostname , A record
    resolveHostname(hostname, T_A);

    return 0;
}

/*
 * Perform a DNS query by sending a packet
 * */
void
resolveHostname(unsigned char *host, int query_type)
{
    unsigned char *buf, *qname, *reader;
    int i, j, stop, sock;
    int len;
    struct sockaddr_in a;
    struct RES_RECORD answers[20], auth[20], addit[20];
    struct sockaddr_in dest;
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;

    printf("Allocating memory...\r\n");
    buf = (unsigned char *) malloc(BUFFER_SIZE);
    if (buf == NULL)
        return;
    bzero(buf, BUFFER_SIZE);

    printf("Resolving %s\r\n", host);

    dns = (struct DNS_HEADER *) buf;

    dns->id = htons((unsigned short) (0xffffu & getpid()));
    dns->rd = 1;
    dns->q_count = htons(1);

    //point to the query portion
    len = sizeof (struct DNS_HEADER);
    qname = (unsigned char*) (buf + len);

    encodeHostname(qname, host);
    len += (strlen((const char *) qname) + sizeof (unsigned char));
    qinfo = (struct QUESTION*) (buf + len); //fill it

    qinfo->qtype = htons(query_type); //type of the query , A , MX , CNAME , NS etc
    qinfo->qclass = htons(1); //its internet (lol)
    len += sizeof (struct QUESTION);

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(dns_servers[0]);
    i = sizeof (struct sockaddr_in);
    
    printf("Sending Packet...");
    if (sendto(sock, (char*) buf, len,
            0, (struct sockaddr*) &dest, sizeof (dest)) < 0)
    {
        perror("failed\r\n");
        free(buf);
        buf = NULL;
        return;
    }
    printf("done\r\n");

    printf("Receiving answer...");
    if (recvfrom(sock, (char*) buf, BUFFER_SIZE, 0, (struct sockaddr*) &dest, (socklen_t*) & i) < 0)
    {
        perror("failed\r\n");
        free(buf);
        buf = NULL;
        return;
    }
    printf("done\r\n");

    dns = (struct DNS_HEADER*) buf;

    //move ahead of the dns header and the query field
    reader = &buf[sizeof (struct DNS_HEADER) + (strlen((const char*) qname) + 1) + sizeof (struct QUESTION)];

    printf("\nThe response contains : ");
    printf("\n %d Questions.", ntohs(dns->q_count));
    printf("\n %d Answers.", ntohs(dns->ans_count));
    printf("\n %d Authoritative Servers.", ntohs(dns->auth_count));
    printf("\n %d Additional records.\n\n", ntohs(dns->add_count));

    //Start reading answers
    stop = 0;

    for (i = 0; i < ntohs(dns->ans_count); i++)
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

    //read authorities
    for (i = 0; i < ntohs(dns->auth_count); i++)
    {
        auth[i].name = decodeHostname(reader, buf, &stop);
        reader += stop;

        auth[i].resource = (struct R_DATA*) (reader);
        reader += sizeof (struct R_DATA);

        auth[i].rdata = decodeHostname(reader, buf, &stop);
        reader += stop;
    }

    //read additional
    for (i = 0; i < ntohs(dns->add_count); i++)
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

    //print answers
    printf("\nAnswer Records : %d \n", ntohs(dns->ans_count));
    for (i = 0; i < ntohs(dns->ans_count); i++)
    {
        printf("Name : %s ", answers[i].name);

        if (ntohs(answers[i].resource->type) == T_A) //IPv4 address
        {
            long *p;
            p = (long*) answers[i].rdata;
            a.sin_addr.s_addr = (*p); //working without ntohl
            printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        }

        if (ntohs(answers[i].resource->type) == 5)
        {
            //Canonical name for an alias
            printf("has alias name : %s", answers[i].rdata);
        }

        free(answers[i].name);
        free(answers[i].rdata);
        printf("\n");
    }

    //print authorities
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

    //print additional resource records
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
            lock++; //or lock=i+1;
        }
    }
    *dns++ = '\0';
}