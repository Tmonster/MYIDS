#ifndef __myStructsc__INCLUDED__
#define __myStructsc__INCLUDED__
/*
The design for the packet structures in this code borrows heavily from the tcpdump.org/pcap.html site
I must give credit where credit is due. The authro Tim Carstens wrote a beautiful introduction to packet sniffing
*/
extern int Ipsrc[4];
extern int Ipdst[4];
typedef u_int tcp_seq;
#define ETHER_ADDR_LEN 6
struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
};
struct sniff_tcp {
        u_short th_sport;       /* source port */
        u_short th_dport;       /* destination port */
        tcp_seq th_seq;         /* sequence number */
        tcp_seq th_ack;         /* acknowledgement number */
        u_char th_offx2;        /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;         /* window */
        u_short th_sum;         /* checksum */
        u_short th_urp;         /* urgent pointer */
};
struct sniff_ip {
        u_char ip_vhl;          /* version << 4 | header length >> 2 */
        u_char ip_tos;          /* type of service */
        u_short ip_len;         /* total length */
        u_short ip_id;          /* identification */
        u_short ip_off;         /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char ip_ttl;          /* time to live */
        u_char ip_p;            /* protocol */
        u_short ip_sum;         /* checksum */
        u_int32_t ip_src,ip_dst; /* source and dest address */
};

struct sniff_udp{
        u_short udp_sport;
        u_short udp_dport;
        u_short udp_len;
        u_short udp_checksum;
        u_short udp_tId;        /*transaction ID*/
        u_short udp_flags;
        u_short udp_questions;
        u_short udp_ARR;
        u_short udp_AuthArr;
        u_short udp_AddArr;
};
struct sniff_dns{
        u_short dns_id;
        u_short dns_qr_flags; //QR 0 for query generation, 1 for response. //Opcode, AA, TC, RD
        u_short dns_qcount;
        u_short dns_acount;
        u_short dns_nscount;
        u_short addr_count;
};

struct sniff_arp{
        u_int16_t arp_ht;                        //Hardware type
        u_int16_t arp_pt;                        //protocol type
        u_int8_t arp_hz;                         //harware size
        u_int8_t arp_pz;                         //protocol size
        u_int16_t arp_op;                        //opcode
        u_char arp_sha[ETHER_ADDR_LEN]; //sender hardware address
        u_char arp_sip[4];                      //sender IP address
        u_char arp_tha[ETHER_ADDR_LEN]; //target hardware address
        u_char arp_tip[4];                      //target IP address
};
struct sniff_answer{
        u_short answer_name;
        u_short answer_Type;
        u_short answer_class;
        u_int32_t answer_ttl;
        u_short answer_length;
        u_int32_t answer_ip;
};
struct MACS_IPS{
        int IP[4];
        u_char MacAddr[6];
};

struct MacIP_list{
        struct MACS_IPS entry;
        struct MacIP_list *next;
};

void printIp(int Ip[4]);
void printmappings(struct MacIP_list *mappings);
bool checkIpAddresses(int Ipsrc[4], int Ipdst[4]);
bool fromInsideTheHouse(int Ipsrc[4]);
void getIp(u_int32_t Ip, int arr[4]);
bool ipsEqual(int Ip1[4], int Ip2[4]);
bool macsEqual(const char mac1[6], const char mac2[6]);
void printMac(const u_char mac[6]);
void printmappings(struct MacIP_list *mappings);

#endif
