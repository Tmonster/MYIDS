#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <string.h>
#include "myStructs.h"
#define ETHER_TYPE_IP (0x0800)
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
/*
The main function  in this code borrows heavily from the tcpdump.org/pcap.html site
I must give credit where credit is due. 
The author Tim Carstens wrote a beautiful introduction to packet sniffing
And I would like to thank him.
*/
int main(int argc, char* argv[]){
	
	char errbuf[PCAP_ERRBUF_SIZE];
	
	//Read the Sinkhole file and store the sinkholes
	FILE *sinkholeF;
	sinkholeF = fopen("sinkholes.txt","r");
	int ch;
	int numSinkholes = 0;
	do{
		ch = fgetc(sinkholeF);
		if(ch == '\n') numSinkholes++;
	} while( ch != EOF);
	
	fclose(sinkholeF);
	int sinkholes[numSinkholes][4];
	int curSinkhole = 0;
	char ch2;
	sinkholeF = fopen("sinkholes.txt", "r");
	while(!feof(sinkholeF)){
		fscanf(sinkholeF, "%d%c", &sinkholes[curSinkhole][0], &ch2);
		fscanf(sinkholeF, "%d%c", &sinkholes[curSinkhole][1], &ch2);
		fscanf(sinkholeF, "%d%c", &sinkholes[curSinkhole][2], &ch2);
		fscanf(sinkholeF, "%d", &sinkholes[curSinkhole][3]);
		curSinkhole++;
	}

	struct MacIP_list *mappings = NULL;

	struct pcap_pkthdr header;
		/**************************************************
		 *struct timeval ts 
		 *bpf_u_int32 caplen; //length of portion present
		 *bpf_u_int32 len; //length of packet (off wire) 
		 **************************************************/
	const u_char *packet;
	pcap_t *handle;
	//IIS pattern detection array initialization
	const char *IIspatterns[15];
	IIspatterns[0] = "%255c";
	IIspatterns[1] = "%25%35%63";
	IIspatterns[2] = "%252f";
	IIspatterns[3] = "%%35c";
	IIspatterns[4] = "%%35%63";
	IIspatterns[5] = "%C1%1C";
	IIspatterns[6] = "%C1%9C";
	IIspatterns[7] = "%C0%AF";
	IIspatterns[8] = "%c1%1c";
	IIspatterns[9] = "%c0%af";
	IIspatterns[10] = "%c0%qf";
	IIspatterns[11] = "%c1%9c";
	IIspatterns[12] = "%c1%af";
	IIspatterns[13] = "%80%af";
	IIspatterns[14] = "\%e0\%80%af";
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_arp *arp;		//the arp header
	const struct sniff_udp *udp;		// The udp header
	const char *payload;                    /* Packet payload */

	bool spoofed = false;

	int size_ip;
	int size_tcp;
	int size_payload;
	u_char protocol;

	unsigned long current_ts=0;

	if (argc < 2){
		printf("Usage: %s filename\n", argv[0]);
		return 2;
	}
	handle = pcap_open_offline(argv[1], errbuf);
	if(handle == NULL) {
		fprintf(stderr, "couldn't open pcap file %s: %s\n", argv[1], errbuf);
		return (2);
	}	
	int cur_counter = 0;
	int pkt_counter = 0;
	int byte_counter = 0;
	while (packet = pcap_next(handle, &header)){
		u_char *pkt_ptr = (u_char *)packet;
		byte_counter += header.len;
		pkt_counter++;
		ethernet = (struct sniff_ethernet*)(packet);
		if(ntohs(ethernet->ether_type) == 0x0806){ 
			//if arp packet  overlay arp packet sniffer
			arp = (struct sniff_arp*)(packet + SIZE_ETHERNET);
			if(ntohs(arp->arp_op) == 2){ // check only replies
				for(int j = 0; j < 4; j++){
					//get Source Ip and Dest Ip
					Ipsrc[j] = (int)arp->arp_sip[j];
					Ipdst[j] = (int)arp->arp_tip[j];
				}
				//initialize the mappings if it is not already done
				if(mappings == NULL){
					mappings = (struct MacIP_list*)malloc(sizeof(struct MacIP_list));
					for(int j = 0; j < 6; j++){
						if(j < 4) mappings->entry.IP[j] = Ipsrc[j];
						mappings->entry.MacAddr[j] = arp->arp_sha[j];
					}
					mappings->next = NULL;
				}
				else{
					//printmappings(mappings);
					struct MacIP_list* head = mappings;
					bool matched = false;
					do{ //You know the list isn't empty because its been checked.
					    //but you want to keep a pointer to the last element
						if(ipsEqual(Ipsrc, head->entry.IP)){
							if(!macsEqual((const char*)arp->arp_sha,(const char*)head->entry.MacAddr)){
								printf("[Potential ARP spoofing]: ip:");
								printIp(Ipsrc);
								printf(", old:");
								printMac(head->entry.MacAddr);
								printf(", new:");
								printMac(arp->arp_sha);
								printf("\n");
								for(int k = 0; k < 6; k++){
									head->entry.MacAddr[k] = arp->arp_sha[k];
								}
							}
							matched = true;
						} 
						head = head->next;
					}while(head != NULL && !matched);
					if(!matched){
						struct MacIP_list *new = (struct MacIP_list*)malloc(sizeof(struct MacIP_list));
						for(int j = 0; j < 6; j++){
							if(j < 4) new->entry.IP[j] = Ipsrc[j];
							new->entry.MacAddr[j] = arp->arp_sha[j];
						}
						new->next = mappings;
						mappings = new;
					}
				}
				
			}
		}
		if(ntohs(ethernet->ether_type) == 0x0800){//if IP packet
			ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
			protocol = ip->ip_p;
			size_ip = ((ip->ip_vhl) & 0x0f)*4;
			getIp(ip->ip_src, Ipsrc);
                        getIp(ip->ip_dst, Ipdst);
			//check if spoofed
			bool spoofed = checkIpAddresses(Ipsrc, Ipdst);
			if(spoofed){
				//check if it is NTP DDoS potentially
				//check protocol
				if(protocol == 17){
					udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
					//check for ntp
					if(ntohs(udp->udp_dport) == 123){
						if((uint16_t)(ntohs(udp->udp_flags)<<8) == 10752){
							printf("[NTP DDoS]: vic:");
							printIp(Ipsrc);
							printf(", srv:"); printIp(Ipdst);
							printf("\n");
						} 
					}
				}
				continue;
			}		
			if(protocol == 6){ /*TCP protocol */
				tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
				if(((tcp->th_flags)>>1)%2 == 1 && !fromInsideTheHouse(Ipsrc) &&
				   ((tcp->th_flags)>>4)%2 == 0){
					printf("[Attempted server connection]: rem:");
					printIp(Ipsrc);
					printf(", srv:");printIp(Ipdst);
					printf(", port:%d\n", ntohs(tcp->th_dport));
				}
				else if(((tcp->th_flags)>>4)%2 == 1 && 
					((tcp->th_flags)>>1)%2 == 1 && fromInsideTheHouse(Ipsrc)){
					printf("[Accepted server connection]: rem:");
					printIp(Ipdst);
					printf(", srv:");printIp(Ipsrc);
					printf(", port:%d\n", ntohs(tcp->th_sport));	
				}
				//check dest port 80 for Http requests
				//because SOMEBODY can't stop downloading SONIC THE HEDGHOG from 1991
				if(ntohs(tcp->th_dport) == 80){
					uint8_t *base = (uint8_t*)(packet + SIZE_ETHERNET + size_ip);
					uint8_t *firstcase = (uint8_t*)(base + (((tcp)->th_offx2 & 0xf0) >> 4)*4);
					const char  *stuffs = (char*)(firstcase);
					//check if get, then find malicious unicode pattern
					if(strstr(stuffs, "GET") != NULL){
						for(int i = 0; i < 15; i++){
							if(strstr(stuffs, IIspatterns[i]) != NULL){
								printf("[Unicode IIS exploit]: src:");
								printIp(Ipsrc);printf(", dst:");
								printIp(Ipdst);printf("\n");
							}
						}
					}
				}
			}
			else if(protocol == 17){ /*UDP protocol*/
				udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
				if(ntohs(udp->udp_sport) != 53) continue;
				int udpsize = udp->udp_len;
				short questions = htons(udp->udp_questions);
				short responses = htons(udp->udp_ARR);
				short AuthResponses = htons(udp->udp_AuthArr);
				short AddResponses = htons(udp->udp_AddArr);
				char *host = NULL;
				short *Type = NULL;
				short *class = NULL;
				int numComponents = 0;  	//number of host components
				int components[100];   		//gamble that there will be no more than 
								//100 components in a host. I mean, who would do that?
				char* hosts[questions];      
				int numHosts = 0;

				uint8_t *componentLength = 0;
				int runningcomponentLength = 0;
				for(int i = 0; i < questions; i++){
					numComponents = 0;
					if(i == 0){
						host = (char*)(packet + SIZE_ETHERNET +
                                                        size_ip + sizeof(struct sniff_udp) + sizeof(char));
					}
					else host = (char*)(class + sizeof(class));
				
					componentLength = (uint8_t*)(packet + SIZE_ETHERNET +
                                        				size_ip + sizeof(struct sniff_udp));
					components[numComponents] = *componentLength;	
					numComponents++;
					while(*componentLength != 0){
						componentLength = (uint8_t*)(componentLength + 
									(1+*componentLength)*sizeof(char));
						components[numComponents] = *componentLength;
						numComponents++;
					}
					for(int j = 0; j < numComponents-2; j++){ 
						//don't need end component=0 or to replace it hence -2
						host[components[j]+runningcomponentLength] = '.';
						runningcomponentLength+=components[i];
					}
					hosts[i] = host; //put in host array so you can print it when analyzing reponse
							//headers
					Type = (short*)(host + (strlen(host)+1)*sizeof(uint8_t));
					class = (short*)(Type + 1);
				}
				uint8_t *answer_name[2];
                                uint16_t *answer_Type;
                                uint16_t *answer_class;
                                u_char *answer_ttl[4];
                                uint16_t *answer_length;
                                u_char *answer_ip[4];
                                getIp(ip->ip_dst, Ipdst);
                                for(int r = 0; r < responses; r++){
                                        if(r == 0){
                                                answer_name[0] = (uint8_t*)(class+1);
                                                answer_name[1] = (uint8_t*)(answer_name[0] + 1);
                                        } else {
                                                answer_name[0] = (uint8_t*)(answer_name[0] + 12 + ntohs(*answer_length));
                                                answer_name[1] = (uint8_t*)(answer_name[0] + 1);
                                                if(false){
                                                        printf("%d is answer length\n", ntohs(*answer_length));
                                                        printf("%d::%d\n", *answer_name[0], *answer_name[1]);
                                                }
                                        }
                                        answer_Type = (uint16_t*)(answer_name[1]+1);
                                        answer_class = (uint16_t*)(answer_Type + 1);
                                        //intialize each one indibvidually because pointer arithmatic is HORRZIIBLE
                                        answer_ttl[0] = (u_char*)(answer_class+1);
                                        answer_ttl[1] = (u_char*)(answer_ttl[0] + 1);
                                        answer_ttl[2] = (u_char*)(answer_ttl[1] + 1);
                                        answer_ttl[3] = (u_char*)(answer_ttl[2] + 1);
                                        answer_length = (uint16_t*)(answer_ttl[3] + 1);
					answer_ip[0] = (u_char*)(answer_length+1);
                                        answer_ip[1] = (u_char*)(answer_ip[0] + 1);
                                        answer_ip[2] = (u_char*)(answer_ip[1] + 1);
                                        answer_ip[3] = (u_char*)(answer_ip[2] + 1);
                                        //only want A type answers
					if(ntohs(*answer_Type) != 1) continue;
                                        for(int l = 0; l < 4; l++){
                                                Ipsrc[l] = (int)(*answer_ip[l]);
                                        }

					for(int i = 0; i < numSinkholes; i++)
					{
						for(int j = 0; j < 4; j++){
							if(Ipsrc[j] != sinkholes[i][j]){
								break;
							}
							if(j == 3){
								printf("[Sinkhole lookup]: src:");
								printIp(Ipdst);
								printf(", host:%s, ip:", hosts[r]);
								printIp(sinkholes[i]);
								printf("\n");
							}
						}
					}
				}
			}
			else if(protocol == 4){ /*IP in IP protocol */
				getIp(ip->ip_src, Ipsrc);
				getIp(ip->ip_dst, Ipdst);
				spoofed = checkIpAddresses(Ipsrc, Ipdst);
			}
		}
		
	
	} //end internal loop for reading packets (all in one file) 
 
    	pcap_close(handle);  //close the pcap file 
	printf("Analyzed %d packets, %d bytes\n", pkt_counter, byte_counter);
        return 0;
}
