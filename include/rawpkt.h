#ifndef RAWPKT_H
#define RAWPKT_H

#define ETH_ALEN    6

#define IPVERSION   4
#define MAXTTL      255
#define IPDEFTTL    64

#define IPTOS_TOS_MASK    0x1E
#define IPTOS_TOS(tos)    ((tos)&IPTOS_TOS_MASK)

#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY    0x10
#define IPTOS_THROUGHPUT  0x08
#define IPTOS_RELIABILITY 0x04
#define IPTOS_MINCOST     0x02
#endif

/* IP flags. */
#ifndef IP_CE
#define IP_CE             0x8000  /* Flag: "Congestion"		*/
#define IP_DF             0x4000  /* Flag: "Don't Fragment"	*/
#define IP_MF             0x2000  /* Flag: "More Fragments"	*/
#define IP_OFFSET         0x1FFF  /* "Fragment Offset" part	*/
#endif

#define IP_FRAG_TIME      (30 * HZ)  /* fragment lifetime	*/


#pragma pack( push, 1 )

typedef struct {
  BYTE   h_dest[ETH_ALEN];      /* destination eth addr */
  BYTE   h_source[ETH_ALEN];    /* source ether addr    */
  WORD   h_proto;               /* packet type ID field */
} eth_packet_t;

typedef struct {
  BYTE   ver_ihl;
  BYTE   tos;
  WORD   tot_len;
  WORD   id;
  WORD   frag_off;
  BYTE   ttl;
  BYTE   protocol;
  WORD   check;
  DWORD  saddr;
  DWORD  daddr;
} ip_packet_t;

typedef struct {
  WORD   source;
  WORD   dest;
  DWORD  seq;
  DWORD  ack_seq;
  WORD   res1:4,
         doff:4,
         fin:1,
         syn:1,
         rst:1,
         psh:1,
         ack:1,
         urg:1,
         ece:1,
         cwr:1;
  WORD   window;
  WORD   check;
  WORD   urg_ptr; 
} tcp_packet_t;

typedef struct {
  WORD   source;
  WORD   dest;
  WORD   len;
  WORD   check;
} udp_packet_t;

typedef struct {
  BYTE   type;
  BYTE   code;
  WORD   check;
  WORD   identifier;
  WORD   seq;
} icmp_packet_t;

#pragma pack(pop)

#define RAWPKT_ICMP_ECHO_REQUEST   8
#define RAWPKT_ICMP_ECHO_REPLY     0

#define RAWPKT_ETHER_HDR_SIZE      14
#define RAWPKT_IP_HDR_SIZE         20
#define RAWPKT_UDP_HDR_SIZE        8
#define RAWPKT_ICMP_HDR_SIZE       8

#define RAWPKT_IP_HDR_LEN          (sizeof(ip_packet_t))
#define RAWPKT_RAW_IP_HDR_LEN      (sizeof(eth_packet_t) + RAWPKT_IP_HDR_LEN)

#endif /* RAWPKT_H */
