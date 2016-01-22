#include "bouncer.h"

#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14

	/* Ethernet header */
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
		struct in_addr ip_src,ip_dst; /* source and dest address */
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

struct sniff_icmp {
	u_char icmp_type;	/* ICMP type */
	u_char icmp_code;	/* ICMP code */
	u_short icmp_sum;	/* ICMP checksum */
	u_short icmp_identifier;	/* ICMP identifier */
	u_short icmp_sequence;	/* ICMP sequence number */
	u_long icmp_payload;	/* ICMP data */
};

/* Prototypes */
uint16_t checksum(void* vdata, u_short length);
int process_icmp(const struct sniff_icmp *icmp, u_short length);
void process_pkt(u_char *args, const struct pcap_pkthdr *header, const u_char *p);
int add_dict(DICT* dictionary_temp, u_short key, struct in_addr value);
int position_dict(DICT* dictionary_temp, u_short key);
int remove_dict(DICT* dictionary_temp, u_short key);
int exist_dict(DICT* dictionary_temp, u_short key);
int fetch_dict(DICT* dictionary_temp, u_short key, struct in_addr* add_fetch);


void process_pkt(u_char *args, const struct pcap_pkthdr *header,
	const u_char *p){

	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_icmp *icmp; /* The ICMP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;

	ethernet = (struct sniff_ethernet*)(p);
	ip = (struct sniff_ip*)(p + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* Check evil bit */
	if ( (((ip->ip_off) & IP_RF) >> 15) == 1 ){
		printf("Evil bit set to 1. Discard packet.");
		return;
	}

	/* Check IP version */
	if (IP_V(ip) != 4) {
		printf("Invalid IP version (not 4).");
		return;
	}

	/* Check if TTL is zero */
	if ((ip->ip_ttl) == 0) {
		printf("TTL is zero, packet discard");
		return;
	}

	u_short size_ip_payload = 0;
	/* Size of the payload of the IP packet */
	if((ip->ip_len)>size_ip){
		size_ip_payload = (ip->ip_len) - size_ip;
	}
	else{
		printf("   * Invalid IP total length: %u bytes\n", (ip->ip_len));
		return;
	}

	/* determine protocol */
	// For ICMP and TCP, we continue the checking. For others protocols, we leave the function.
	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("Protocol: TCP\n");
			// TODO Appel fonction TCP
			
			tcp = (struct sniff_tcp*)(p + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;

			// TODO !!!! The check of the tcp size should be in the function process_tcp.
			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}

			return;
		case IPPROTO_ICMP:
			printf("Protocol: ICMP\n");
			
			icmp = (struct sniff_icmp*) (p + SIZE_ETHERNET + size_ip);
			switch (process_icmp(icmp, size_ip_payload)){
				case 1:
					printf("Echo request.");
					// TODO DONE -add the couple (icmp_id, sending_address) to the hash.
					//		-change the sending address and receiving address in the IP packet.
					//		-recalculate the checksum.
					//		-send the packet.
					if(add_dict(dictionary, (icmp->icmp_identifier), (ip->ip_src)) != 1){
						printf("Error while adding an entry in dict.");
						return;
					}
					

				case 2:
					printf("Echo Reply.");
					// TODO DONE -check if the id is in dict.
					//		-change the receiving address in the IP packet.
					//		-recalculate the checksum.
					//		DONE -clear the dict entry.
					//		-send the packet.
					if(exist_dict(dictionary, (icmp->icmp_identifier)) != 1){
						printf("Echo Reply with unknow id. Packet discarded.");
						return;
					}

					if(remove_dict(dictionary, (icmp->icmp_identifier)) != 1){
						printf("Error while removing an entry from dict.");
					}

				default:
					printf("Packet discarded.\n");
			}
			break;
		default:
			printf("Protocol not taken in charge.\n");
			return;
	}	

	// payload = (u_char *)(p + SIZE_ETHERNET + size_ip + size_tcp);

	printf("a packet received of length: %u\n", size_ip);

	return;

	
	/* Define pointers for packet's attributes */
	
	/* Check IP header */

	/* Check type of packet and process */

	
	/* Check ICMP header */
	/* Check TCP header */
	/* Check FTP header */

	/* Send processed packet */
};

/* Check the ICMP packet. Return 0 if something is wrong with the packet, 1 if it's a request, 2 if it's a reply */
int process_icmp(const struct sniff_icmp *icmp, u_short length){

	/* Check Code (=0) */
	if ((icmp->icmp_code) != (u_char) 0){
		printf("Bad ICMP code. Discard packet.\n");
		return 0;
	}

	/* Check checksum */
	/* Copy the ICMP packet */
	struct sniff_icmp icmp_copy = (struct sniff_icmp) *icmp;
	/* Empty the checksum field of the copy */
	icmp_copy.icmp_sum = 0x0000;
	/* Calculate the checksum of the copy */
	uint16_t check_copy = checksum(&icmp_copy, length);
	/* Compare the calculated checksum with the one of the packet */
	if ((icmp->icmp_sum) != (u_short) check_copy){
		printf("Wrong ICMP checksum. Discard packet.\n");
		return 0;
	}

	/* Check Type (=0 or 8) */
	switch (icmp->icmp_type) {
		case 0:
			printf("ICMP reply.\n");
			return 2;
		case 8:
			printf("ICMP request.\n");
			return 1;
		default:
			printf("Bad ICMP ping type. Discard packet.\n");
			return 0;
	}

	/* Default return */
	return 0;
};

/* Calculate the checksum of an ip prtocol header. */
// Attention : peut-être changer les types dans cette fonction.
uint16_t checksum(void* vdata, u_short length){
	// Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    u_short i;
    // Handle complete 16-bit blocks.
    for (i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
};

/* Functions to manipulate the dictionary of (ICMP_id, IP_address) */
int add_dict(DICT* dictionary_temp, u_short key, struct in_addr value){
	// What to do if the key already is in the dict?
	int i=0;
	while(i<100 && (dictionary_temp->id_array)[i]!=(u_short) 0){
		i++;
	}

	if(i<100){
		(dictionary_temp->id_array)[i] = key;
		(dictionary_temp->add_array)[i] = value;
		return 1;
	}

	return 0;
};

int exist_dict(DICT* dictionary_temp, u_short key){
	int i = 0;
	while(i<100 && (dictionary_temp->id_array)[i] != key){
		i++;
	}

	if(i!=100){
		return 1;
	}

	return 0;
};

int position_dict(DICT* dictionary_temp, u_short key){
	int i = 0;
	while(i<100 && (dictionary_temp->id_array)[i] != key){
		i++;
	}
	return i;
};

int remove_dict(DICT* dictionary_temp, u_short key){
	int j = position_dict(dictionary_temp, key);
	if(j!=100){
		(dictionary_temp->id_array)[j] = (u_short) 0;
		return 1;
	}
	return 0;
};

int fetch_dict(DICT* dictionary_temp, u_short key, struct in_addr* add_fetch){
	int j = position_dict(dictionary_temp, key);
	if(j!=100){
		add_fetch = &(dictionary_temp->add_array)[j];
		return 1;
	}
	return 0;
};