#ifndef TOMAHAWK_H
#define TOMAHAWK_H

/* ************** Macro **************************** */
#define LOG "log.txt"
#define RECORD "record.txt"

#define MSG(fmt...)\
do{\
	printf(fmt);\
	fflush(stdout);\
}while(0)

#ifdef DEBUG
#define DBG(fmt...)\
do{\
	FILE *fd;\
	fd = fopen(LOG, "a+");\
/*	fprintf(fd, "<%s><%s><%d> ", __FILE__, __func__, __LINE__);*/\
	fprintf(fd, fmt);\
	fprintf(stdout, "<%s><%s><%d> ", __FILE__, __func__, __LINE__);\
	fprintf(stdout, fmt);\
	fflush(stdout);\
	fclose(fd);\
}while(0)
#define PRINT_BYTES(addr, len)\
do{\
	uint8_t *array = (uint8_t *)addr;\
	int32_t index = 0;\
	for (; index < len; ++index) {\
		fprintf(stdout, "%.2x ", array[index]);\
		if (index % 16 == 15)\
			fprintf(stdout, "\n");\
	}\
	fprintf(stdout, "\n");\
}while(0)
#else
#define DBG(fmt...)
#define PRINT_BYTES(addr, len)
#endif

#define EXIT(fmt...)\
do{\
	system("touch commond_end");\
	FILE *fd;\
	fd = fopen(RECORD, "a+");\
/*	fprintf(fd, "<%s><%s><%d> ", __FILE__, __func__, __LINE__);*/\
	fprintf(fd, fmt);\
	fprintf(stdout, "<%s><%s><%d> ", __FILE__, __func__, __LINE__);\
	fprintf(stdout, fmt);\
	fflush(stdout);\
	fclose(fd);\
	exit(-1);\
}while(0)

/* ************** Structures *************************** */
typedef struct {
	uint32_t id;
	uint32_t interface;
	uint32_t sec;
	uint32_t usec;
	uint8_t *buf;
	uint32_t len;
	uint32_t payload_offset;
}Packet;

typedef union {
	uint32_t ipv4;
	uint8_t ipv6[16];
	uint32_t ipv6_4[4];
}ip_addr_t;

typedef struct {
	uint32_t pkt_cap;
	uint32_t pkt_num;
	Packet *pkt;
	int32_t max_sent_id;	/* array id */
	int32_t max_recv_id1;	/* array id */
	int32_t max_recv_id2;	/* array id */
	int8_t *recv_flag;
	int32_t sent_num;
	int32_t recv_num;
/* original client IP addr in file */
	ip_addr_t src;
	ip_addr_t dst;
#define sv4 src.ipv4
#define sv6 src.ipv6
#define dv4 dst.ipv4
#define dv6 dst.ipv6
}Flow;

typedef struct {
	uint32_t flow_cap;
	uint32_t flow_num;
	Flow *flow;
	int32_t max_sending_flow_id;	/* array id */
	int32_t max_recv_flow_id1;		/* array id */
	int32_t max_recv_flow_id2;		/* array id */
	uint32_t total_pkt_num;
	int32_t total_sent_num;
	int32_t total_recv_num;
}Trace;

typedef struct {
/* PC interface info */
	uint8_t device1_name[8];
	uint8_t device2_name[8];
	
	uint8_t device1_ip_str[16];
	uint8_t device2_ip_str[16];
	
	uint8_t device1nat_ip_str[16];
	uint8_t device2nat_ip_str[16];

	uint8_t device1_4to6_str[16];
	uint8_t device2_4to6_str[16];

	ip_addr_t src;
	ip_addr_t dst;
	
	ip_addr_t device1nat;
	ip_addr_t device2nat;

	ip_addr_t device1_4to6;
	ip_addr_t device2_4to6;

#define sv4 src.ipv4
#define sv6 src.ipv6
#define dv4 dst.ipv4
#define dv6 dst.ipv6
#define device1nat4 device1nat.ipv4
#define device1nat6 device1nat.ipv6
#define device2nat4 device2nat.ipv4
#define device2nat6 device2nat.ipv6

	uint8_t device1_mac[8];
	uint8_t device2_mac[8];
/* FW interface info */
	uint8_t fw_mac1_str[20];
	uint8_t fw_mac2_str[20];
	uint8_t fw_mac1[8];
	uint8_t fw_mac2[8];
/* socket info */
	int socket1;
	int socket2;
	struct sockaddr_ll sa1;
	struct sockaddr_ll sa2;
	int socket1_if_flags;
	int socket2_if_flags;
}Interface;

typedef struct {
	uint8_t *name;
	int32_t retrans;
	int32_t timeout;
	int32_t loops;
	int32_t mis;
	int32_t pcap_version;
	int32_t send_version;
	int32_t recv_version;
	int32_t v4tov6;
	int32_t alter_mac;
	int32_t alter_ip;
	uint16_t port;
	uint8_t device1_in_nat;
	uint8_t device2_in_nat;
	
	void (*LoadPacket)(const struct pcap_pkthdr *pcap_hdr, Trace *trace, Flow *flow, 
		const u_char * data);
	int (*Recv_L3_Check)(void *, int, int, int *);
	int (*Recv_L2_Check)(void *, int, int);

}File_info;

typedef struct {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t zero;
	uint8_t protocol;
	uint16_t proto_len;
}Pesudo_hdr;

typedef struct {
	ip_addr_t src;
	ip_addr_t dst;
#define sv4 src.ipv4
#define sv6 src.ipv6
#define dv4 dst.ipv4
#define dv6 dst.ipv6
	uint32_t proto_len;
	uint32_t zero_with_nxt_hdr;
}Pesudo_hdr6;

#endif
