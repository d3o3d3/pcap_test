#include <stdio.h>
#include "tcp.h"

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;

    while (1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("%u bytes captured\n", header->caplen);

        ethernet = (struct sniff_ethernet*)(packet);
        //if it is not ipv4
        //0x0800 network byte order
        if(ethernet->ether_type != htons((u_short)0x0800)) continue;
	    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	    size_ip = IP_HL(ip)*4;
	    if (size_ip < 20) {
		    printf("   * Invalid IP header length: %u bytes\n", size_ip);
            break;
        }
        //if it is not tcp,
        if(ip->ip_p != 6) continue;
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) {
            printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
            break;
        }
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

        //Ethernet Header의 src mac / dst mac
        printf("src mac : %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5]);
        printf("dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->edhost[0],ethernet->edhost[1],ethernet->edhost[2],ethernet->edhost[3],ethernet->edhost[4],ethernet->edhost[5]);
        //IP Header의 src ip / dst ip
        printf("src ip : %s\n", inet_ntoa(ip->ip_src));
        printf("dst ip : %s\n", inet_ntoa(ip->ip_dst)); 
        //TCP Header의 src port / dst port
        printf("src port : %hu\n", ntohs(tcp->th_sport));
        printf("dst port : %hu\n", ntohs(tcp->th_dport));
        //Payload(Data)의 hexadecimal value(최대 16바이트까지만)
        int payload_len = header->caplen - (SIZE_ETHERNET + size_ip + size_tcp);
        if(payload_len > 16){
            for(int i = 0;i<16;i++, payload++) printf("%02hhX ", *payload);
            printf("\n\n");
        }else if(payload_len){
            for(int i = 0;i<payload_len;i++, payload++) printf("%02hhX ", *payload);
            printf("\n\n");
        }else printf("No Payload\n\n");
    }

    pcap_close(handle);
}
