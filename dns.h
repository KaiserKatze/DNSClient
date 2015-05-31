/* 
 * File:   dns.h
 * Author: donizyo
 *
 * Created on May 31, 2015, 5:45 PM
 */

#ifndef DNS_H
#define	DNS_H

#ifdef	__cplusplus
extern "C" {
#endif

#define UDP_BUFFER_CAPACITY 512
#define TCP_BUFFER_CAPACITY 65536

#define T_A         1
#define T_NS        2
#define T_CNAME     5
#define T_SOA       6
#define T_WKS       11
#define T_PTR       12
#define T_HINFO     13
#define T_MINFO     14
#define T_MX        15
#define T_TXT       16
#define T_AAAA      28


#ifdef	__cplusplus
}
#endif

#endif	/* DNS_H */

