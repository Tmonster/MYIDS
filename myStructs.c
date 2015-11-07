#include <pcap.h>
#include <stdlib.h>
#include <stdbool.h>
#include "myStructs.h"


/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
#if 0	/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

	/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	u_int32_t ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
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
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};
#endif


int Ipsrc[4];
int Ipdst[4];

        /* Ethernet header */
struct sniff_ethernet;
struct sniff_tcp;
struct sniff_ip;
struct sniff_udp;
struct sniff_dns;
struct sniff_arp;
struct MACS_IPS;
struct MacIP_list;


void printIp(int Iparr[4]){
        for(int i = 0; i < 3; i++){
                printf("%d.", Iparr[i]);
        }
        printf("%d", Iparr[3]);
}

bool checkIpAddresses(int Ipsrc[4], int Ipdst[4]){
         //if both source and dst are not in home subnet
        if(!(Ipdst[0] == 10 &&
                    Ipdst[1] >= 0 && Ipdst[1] <= 255 &&
                    Ipdst[2] >= 0 && Ipdst[2] <= 255 &&
                    Ipdst[3] >= 1 && Ipdst[3] <= 254)   &&
           !(Ipsrc[0] == 10 &&
                   (Ipsrc[1] >= 0 && Ipsrc[1] <= 255 &&
                    Ipsrc[2] >= 0 && Ipsrc[2] <= 255 &&
                    Ipsrc[3] >= 1 && Ipsrc[3] <= 254)))
        {
                printf("[Spoofed IP address]: src:");
                printIp(Ipsrc);
                printf(", dst:");
                printIp(Ipdst);
                printf("\n");
                return true;
        }
        return false;
}
bool fromInsideTheHouse(int Ipsrc[4]){
        if(Ipsrc[0] == 10 &&
                   (Ipsrc[1] >= 0 && Ipsrc[1] <= 255 &&
                    Ipsrc[2] >= 0 && Ipsrc[2] <= 255 &&
                    Ipsrc[3] >= 1 && Ipsrc[3] <= 254))
        {
                return true;
        }
        return false;
}

void getIp(u_int32_t Ip, int arr[4]){
        arr[0] = (Ip << 24) >> 24;
        arr[1] = (Ip << 16) >> 24;
        arr[2] = (Ip << 8) >> 24;
        arr[3] = (Ip >> 24);
}

bool ipsEqual(int Ip1[4], int Ip2[4]){
        for(int i = 0; i<4; i++){
                if(Ip1[i] != Ip2[i]) return false;
        }return true;
}

bool macsEqual(const char mac1[6],const char mac2[6]){
        for(int i = 0; i < 6; i++){
                if(mac1[i] != mac2[i]) return false;
        } return true;
}
void printMac(const u_char mac[6]){
        for(int i = 0; i < 5; i++) printf("%02X:", mac[i]);
        printf("%02X", mac[5]);
}
void printmappings(struct MacIP_list *mappings){
        int count = 0;
        while(mappings != NULL){
                printf("Mapping %d, IP:",count);
                printIp(mappings->entry.IP);
                printf(", is at mac:");
                printMac(mappings->entry.MacAddr);
                printf("\n");
                mappings=mappings->next;
                count++;
        }
}

