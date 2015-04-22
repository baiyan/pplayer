/*
 * Author: BaiYan
 * Date: 2013-05-09 15:32:00
 * Version: 0.6
 * This is my last modified version of tomahawk in Neusoft.
 * Good Luck.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <stdint.h>
#include <fcntl.h>

#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include "pcap.h"
#include "pcap-int.h"
#include "pplayer.h"


/* ************** Global Variables ********************* */
uint64_t clicksPerUSec;
Interface interface;
File_info my_file;
Trace *t;
/* ************** Functions **************************** */
inline unsigned long long int Clicks()
{
    unsigned long long int x;
    __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
    return x;
}

void Calibrate(void)
{
    uint64_t x1, x2;
    struct timeval start, end;

    x1 = Clicks();
    gettimeofday(&start, NULL);
    usleep(10000);
    x2 = Clicks();
    gettimeofday(&end, NULL);
    end.tv_sec -= start.tv_sec;
    end.tv_usec -= start.tv_usec;
    clicksPerUSec = (x2 - x1)/(end.tv_sec*1000000 + end.tv_usec);
    DBG("start:%llu end:%llu start-end:%llu dt_usec:%lu", x1, x2, x2-x1, (end.tv_sec*1000000 + end.tv_usec));
}

double ReadSysClock ()
{
    return Clicks() / clicksPerUSec / 1000000.0;
}

uint16_t csum(uint8_t *buf, int32_t size)
{
	uint32_t sum = 0;
	while (size > 1) {
		sum += *(uint16_t *)buf;
		buf += 2;
		size -= 2;
	}
	if (size > 0) {
		sum += *(uint8_t *)buf;
	}
	
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (uint16_t)(~sum);
}

uint16_t ip_csum_as(uint8_t *iph, uint32_t ihl)
{
	/* ihl = iph->ihl */
    uint32_t sum;
    
    __asm__ __volatile__(
        "movl (%1), %0 ;\n"
        "subl $4, %2 ;\n"
        "jbe 2f ;\n"
        "addl 4(%1), %0 ;\n"
        "adcl 8(%1), %0 ;\n"
        "adcl 12(%1), %0 ;\n"
    "1:     adcl 16(%1), %0 ;\n"
        "lea 4(%1), %1 ;\n"
        "decl %2 ;\n"
        "jne 1b ;\n"
        "adcl $0, %0 ;\n"
        "movl %0, %2 ;\n"
        "shrl $16, %0 ;\n"
        "addw %w2, %w0 ;\n"
        "adcl $0, %0 ;\n"
        "notl %0 ;\n"
    "2: ;\n"
    : "=r" (sum), "=r" (iph), "=r" (ihl)
    : "1" (iph), "2" (ihl)
    : "memory");
    return(sum);
}

#define ASM 1
inline void ip_csum(struct iphdr *iph)
{
	uint16_t sh;
	iph->check = 0;
#ifdef ASM
	sh = ip_csum_as((uint8_t *)iph, iph->ihl);
#else
	sh = csum((uint8_t *)iph, iph->ihl << 2);
#endif
	iph->check = sh;
}

void tcp_csum(struct iphdr *iph, uint8_t *data)
{
	int tcp_len = 0;
	Pesudo_hdr *piph = NULL;
	struct tcphdr *tcph = NULL;
	static uint8_t box[16000];
	
	tcp_len = ntohs(iph->tot_len) - (iph->ihl << 2);
	if (tcp_len < 20) {
		return;
	} 

	piph = (Pesudo_hdr *)box;
	piph->saddr = iph->saddr;
	piph->daddr = iph->daddr;
	piph->zero = 0;
	piph->protocol = 6;
	piph->proto_len = htons(tcp_len);
	
	tcph = (struct tcphdr *)data;
	tcph->th_sum = 0;
	
	if (tcp_len % 2 == 1) {
		memcpy(box + 12, data, tcp_len);
		box[12 + tcp_len] = 0;
		tcph->th_sum = csum(box, 12 + tcp_len + 1);
	} else {
		memcpy(box + 12, data, tcp_len);
		tcph->th_sum = csum(box, 12 + tcp_len);
	}
}

void tcp_csum6(struct ip6_hdr *iph6, uint8_t *data)
{
	int tcp_len = 0;
	struct tcphdr *tcph = NULL;
	Pesudo_hdr6 *piph6 = NULL;
	static uint8_t box[16000];
	tcp_len = ntohs(iph6->ip6_plen);
	piph6 = (Pesudo_hdr6 *)box;
	memcpy(piph6->sv6, &iph6->ip6_src, 16);
	memcpy(piph6->dv6, &iph6->ip6_dst, 16);
	piph6->proto_len = htonl(tcp_len);
	piph6->zero_with_nxt_hdr = htonl(0x0 | IPPROTO_TCP);
	tcph = (struct tcphdr *)data;
	tcph->th_sum = 0;
	if (tcp_len % 2 == 1) {
		memcpy(box + sizeof(Pesudo_hdr6), data, tcp_len);
		box[sizeof(Pesudo_hdr6) + tcp_len] = 0;
		tcph->th_sum = csum(box, sizeof(Pesudo_hdr6) + tcp_len + 1);
	} else {
		memcpy(box + sizeof(Pesudo_hdr6), data, tcp_len);
		tcph->th_sum = csum(box, sizeof(Pesudo_hdr6) + tcp_len);
	}
}

void udp_csum(struct iphdr *iph, uint8_t *data)
{
	int udplen = 0;
	Pesudo_hdr *piph = NULL;
	struct udphdr *udph = NULL;
	static uint8_t box[16000];
	
	udplen = ntohs(iph->tot_len) - (iph->ihl << 2);
	if (udplen < 20) {
		return;
	}
	piph = (Pesudo_hdr *)box;
	piph->saddr = iph->saddr;
	piph->daddr = iph->daddr;
	piph->zero = 0;
	piph->protocol = 17;
	piph->proto_len = htons(udplen);
	udph = (struct udphdr *)data;
	udph->uh_sum = 0;
	if (udplen % 2 == 1) {
		memcpy(box + sizeof(Pesudo_hdr), data, udplen);
		box[sizeof(Pesudo_hdr) + udplen] = 0;
		udph->uh_sum = csum(box, sizeof(Pesudo_hdr) + udplen + 1);
	} else {
		memcpy(box + sizeof(Pesudo_hdr), data, udplen);
		udph->uh_sum = csum(box, sizeof(Pesudo_hdr) + udplen);
	}
}

void udp_csum6(struct ip6_hdr *iph6, uint8_t *data)
{
	int udp_len = 0;
	struct udphdr *udph = NULL;
	Pesudo_hdr6 *piph6 = NULL;
	static uint8_t box[16000];
	udp_len = ntohs(iph6->ip6_plen);
	piph6 = (Pesudo_hdr6 *)box;
	memcpy(piph6->sv6, &iph6->ip6_src, 16);
	memcpy(piph6->dv6, &iph6->ip6_dst, 16);
	piph6->proto_len = htonl(udp_len);
	piph6->zero_with_nxt_hdr = htonl(0x0 | IPPROTO_UDP);
	udph = (struct udphdr *)data;
	udph->uh_sum = 0;
	if(udp_len % 2 == 1) {
		memcpy(box + sizeof(Pesudo_hdr6), data, udp_len);
		box[sizeof(Pesudo_hdr6) + udp_len] = 0;
		udph->uh_sum = csum(box, sizeof(Pesudo_hdr6) + udp_len + 1);
	} else {
		memcpy(box + sizeof(Pesudo_hdr6), data, udp_len);
		udph->uh_sum = csum(box, sizeof(Pesudo_hdr6) + udp_len);
	}
}	

inline uint16_t NewChecksum (uint16_t check, uint32_t old, uint32_t new)
{
    uint32_t m3, b, c, d, e;
    uint16_t a;

    a = ntohs(check);
    a = ~a;

    old = ntohl(old);
    old = ~old;
    b = old >> 16;
    c = old & 0xffff;

    new = ntohl(new);
    d = new >> 16;
    e = new & 0xffff;

    m3 = a + b + c + d + e;
    m3 = (m3 >> 16) + (m3 & 0xffff);
    m3 = (m3 >> 16) + (m3 & 0xffff);
    check = ~m3;
    return htons(check);
}

uint32_t Reverse(uint32_t x)
{
   x = ( (x & 0x55555555) <<  1 ) | ( (x >>  1) & 0x55555555 );
   x = ( (x & 0x33333333) <<  2 ) | ( (x >>  2) & 0x33333333 );
   x = ( (x & 0x0F0F0F0F) <<  4 ) | ( (x >>  4) & 0x0F0F0F0F );
   x = (x << 24) | ((x & 0xFF00) << 8) |
       ((x >> 8) & 0xFF00) | (x >> 24);
   return x;
}

uint32_t CRC32(uint8_t *message, int32_t msgLength)
{
   int32_t i, j;
   uint32_t byte, crc;

   i = 0;
   crc = 0xFFFFFFFF;
   while (i < msgLength) {
      byte = message[i];            // Get next byte.
      byte = Reverse(byte);         // 32-bit reversal.
      for (j = 0; j <= 7; j++) {    // Do eight times.
         if ((int)(crc ^ byte) < 0)
              crc = (crc << 1) ^ 0x04C11DB7;
         else crc = crc << 1;
         byte = byte << 1;          // Ready next msg bit.
      }
      i = i + 1;
   }
   return Reverse(~crc);
}

int32_t parseEtherAddr(uint8_t *ether, uint8_t *mac)
{
    int32_t i = 0;
    uint8_t *temp;

    while (*ether != '\0' && i<6) {
        temp = ether;
		while (*ether != '\0' && *ether != ':') {
	    	ether++;
		}
		if (*ether == ':') {
	    	ether++;
		}
		mac[i++] = (u_char)strtol((const char *)temp, NULL, 16);
    }
    return (i == 6);
}

int32_t get_interface_info(char* name)
{
	FILE *fp = NULL;
	char buff[256],*p = NULL;

	char* eth1name="device1:";
	char* eth2name="device2:";
	
	char* eth1ip="device1ip:";
	char* eth2ip="device2ip:";
	
	char* device1nat="device1nat:";
	char* device2nat="device2nat:";

	char* v4tov61 = "device1-4to6:";
	char* v4tov62 = "device2-4to6:";
	
	char* fwmac1="fwmac1:";
	char* fwmac2 = "fwmac2:";
	
	if (!(fp=fopen(name, "r"))) {
		DBG("call fopen profile failed! %s\n", strerror(errno));
		return -1;
	}
	
	for (;;) {
		if (!fgets(buff,255,fp)) {
				break;
		}
		p = buff;
		//滤除空格和制表符
		while (*p==32 || *p==9) {	
			p++;
		}
		/*注释或回车符*/
		if (!*p || *p=='#' || *p==';' || ( *p=='/' && *(p+1)=='/') || *p==13 || *p==10 ) {
			continue;
		}
		
		if (p[strlen(p) - 1] == '\n') {
			p[strlen(p) - 1] = '\0';
		}
		
		if (!memcmp(p, eth1name, 8)) {
			memcpy(interface.device1_name, p+8, 4);
			continue;
		}
		if (!memcmp(p, eth2name, 8)) {
			memcpy(interface.device2_name, p+8, 4);
			continue;
		}
		if (!memcmp(p, eth1ip, 10)) {
			memcpy(interface.device1_ip_str, p+10, strlen(p)-10);
			continue;
		}
		if (!memcmp(p, eth2ip, 10)) {
			memcpy(interface.device2_ip_str, p+10, strlen(p)-10);
			continue;
		}
	
		if (!memcmp(p, device1nat, 11)) {
			memcpy(interface.device1nat_ip_str, p+11, strlen(p)-11);
			continue;
		}
		
		if (!memcmp(p, device2nat, 11)) {
			memcpy(interface.device2nat_ip_str, p+11, strlen(p)-11);
			continue;
		}

		if (!memcmp(p, v4tov61, 13)) {
			memcpy(interface.device1_4to6_str, p+13, strlen(p)-13);
			continue;
		}
		
		if (!memcmp(p, v4tov62, 13)) {
			memcpy(interface.device2_4to6_str, p+13, strlen(p)-13);
			continue;
		}
		
		if (!memcmp(p, fwmac1, 7)) {
			memcpy(interface.fw_mac1_str, p+7, strlen(p)-7);
			continue;
		}
		if (!memcmp(p, fwmac2, 7)) {
			memcpy(interface.fw_mac2_str, p+7, strlen(p)-7);
			continue;
		}
	}
	if (my_file.pcap_version == 4) {
		if (inet_pton(AF_INET, (const char *)interface.device1_ip_str, &interface.sv4) <= 0) {
			DBG("illegal ip address %s in profile\n", interface.device1_ip_str);
			return -1;
		}
		if (inet_pton(AF_INET, (const char *)interface.device2_ip_str, &interface.dv4) <= 0) {
			DBG("illegal ip address %s in profile\n", interface.device1_ip_str);
			return -1;
		}
		if (inet_pton(AF_INET, (const char *)interface.device1nat_ip_str, &interface.device1nat4) <= 0) {
			DBG("illegal ip address %s in profile\n", interface.device1nat_ip_str);
			return -1;
		}
		if (inet_pton(AF_INET, (const char *)interface.device2nat_ip_str, &interface.device2nat4) <= 0) {
			DBG("illegal ip address %s in profile\n", interface.device2nat_ip_str);
			return -1;
		}
		if (my_file.v4tov6) {
			if (inet_pton(AF_INET6, (const char *)interface.device1_4to6_str, &interface.device1_4to6) <= 0) {
				DBG("illegal ip address %s in profile\n", interface.device1_4to6_str);
				return -1;
			}
			if (inet_pton(AF_INET6, (const char *)interface.device2_4to6_str, &interface.device2_4to6) <= 0) {
				DBG("illegal ip address %s in profile\n", interface.device2_4to6_str);
				return -1;
			}
		}
	} else {
		if (inet_pton(AF_INET6, (const char *)interface.device1_ip_str, interface.sv6) <= 0) {
			DBG("illegal ip address %s in profile\n", interface.device1_ip_str);
			return -1;
		}
		if (inet_pton(AF_INET6, (const char *)interface.device2_ip_str, interface.dv6) <= 0) {
			DBG("illegal ip address %s in profile\n", interface.device2_ip_str);
			return -1;
		}
		if (inet_pton(AF_INET6, (const char *)interface.device1nat_ip_str, interface.device1nat6) <= 0) {
			DBG("illegal ip address %s in profile\n", interface.device1nat_ip_str);
			return -1;
		}
		if (inet_pton(AF_INET6, (const char *)interface.device2nat_ip_str, interface.device2nat6) <= 0) {
			DBG("illegal ip address %s in profile\n", interface.device2nat_ip_str);
			return -1;
		}	
	}
	
	if (parseEtherAddr(interface.fw_mac1_str, interface.fw_mac1) != 1) {
		DBG("%s: error fwmac1 in profile %s\n", my_file.name, interface.fw_mac1_str);
		return -1;
	}
	if (parseEtherAddr(interface.fw_mac2_str, interface.fw_mac2) != 1) {
		DBG("%s: error fwmac2 in profile %s\n", my_file.name, interface.fw_mac2_str);
		return -1;
	}
	MSG("device1 name: %s\ndevice2 name: %s\n", interface.device1_name, interface.device2_name);
	MSG("device1 ip: %s\ndevice2 ip: %s\ndevice1nat ip: %s\ndevice2nat ip: %s\n", 
		interface.device1_ip_str,
		interface.device2_ip_str,
		interface.device1nat_ip_str,
		interface.device2nat_ip_str);
	MSG("device1-4to6: %s\ndevice2-4to6: %s\n", 
		interface.device1_4to6_str, interface.device2_4to6_str);
	MSG("fwmac1: %s\nfwmac2: %s\n", interface.fw_mac1_str, interface.fw_mac2_str);
	if (*((int *)(&interface.device1nat4))) {
		my_file.device1_in_nat = 1;
		MSG("device1 is in nat\n");
	}
	if (*((int *)(&interface.device2nat4))) {
		my_file.device2_in_nat = 1;
		MSG("device2 is in nat\n");
	}
#ifdef DEBUG
	char addr[46];
	if (my_file.pcap_version == 4) {
		DBG("device1 ip %s\n", inet_ntop(AF_INET, &interface.sv4, addr, 46));
		DBG("device2 ip %s\n", inet_ntop(AF_INET, &interface.dv4, addr, 46));
		DBG("device1nat ip %s\n", inet_ntop(AF_INET, &interface.device1nat4, addr, 46));
		DBG("device2nat ip %s\n", inet_ntop(AF_INET, &interface.device2nat4, addr, 46));
		DBG("device1-4to6 ip %s\n", inet_ntop(AF_INET6, &interface.device1_4to6, addr, 46));
		DBG("device2-4to6 ip %s\n", inet_ntop(AF_INET6, &interface.device2_4to6, addr, 46));
	} else {
		DBG("device1 ip %s\n", inet_ntop(AF_INET6, &interface.sv6, addr, 46));
		DBG("device2 ip %s\n", inet_ntop(AF_INET6, &interface.dv6, addr, 46));
		DBG("device1nat ip %s\n", inet_ntop(AF_INET6, &interface.device1nat6, addr, 46));
		DBG("device2nat ip %s\n", inet_ntop(AF_INET6, &interface.device2nat6, addr, 46));
	}
	DBG("fw_mac1:");PRINT_BYTES(interface.fw_mac1, 6);
	DBG("fw_mac2:");PRINT_BYTES(interface.fw_mac2, 6);
#endif
	fclose(fp);
	return 0;
}


int get_if_flags(int if_fd, char *eth, int *flags)
{
	struct ifreq ifreq;
	memset(&ifreq, 0, sizeof(ifreq));
	strncpy(ifreq.ifr_name, eth, IFNAMSIZ - 1);
	if (0 > ioctl(if_fd, SIOCGIFFLAGS, &ifreq)) {
		perror("SIOCGIFFLAGS ioctl err: ");
		return -1;
	}
	*flags = ifreq.ifr_ifru.ifru_flags;
	return 0;
}

int set_if_flags(int if_fd, char *eth, int flags)
{
	struct ifreq ifreq;
	memset(&ifreq, 0, sizeof(ifreq));
	strncpy(ifreq.ifr_name, eth, IFNAMSIZ - 1);
	ifreq.ifr_ifru.ifru_flags = flags;
	if (0 > ioctl(if_fd, SIOCSIFFLAGS, &ifreq)) {
		perror("SIOCSIFFALGS ioctl err: ");
		return -1;
	}
	return 0;
}

int add_if_flags(int if_fd, char *eth, int bit)
{
	int flags;
	struct ifreq ifreq;
	memset(&ifreq, 0, sizeof(ifreq));
	strncpy(ifreq.ifr_name, eth, IFNAMSIZ - 1);
	if (0 > ioctl(if_fd, SIOCGIFFLAGS, &ifreq)) {
		perror("SIOCGIFFLAGS ioctl err: ");
		return -1;
	}
	flags = ifreq.ifr_ifru.ifru_flags;
	flags |= bit;	
	ifreq.ifr_ifru.ifru_flags = flags;
	if (0 > ioctl(if_fd, SIOCSIFFLAGS, &ifreq)) {
		perror("SIOCSIFFALGS ioctl err: ");
		return -1;
	}
	return 0;
}

int sub_if_flags(int if_fd, char *eth, int bit)
{
	int flags;
	struct ifreq ifreq;
	memset(&ifreq, 0, sizeof(ifreq));
	strncpy(ifreq.ifr_name, eth, IFNAMSIZ - 1);
	if (0 > ioctl(if_fd, SIOCGIFFLAGS, &ifreq)) {
		perror("SIOCGIFFLAGS ioctl err: ");
		return -1;
	}
	flags = ifreq.ifr_ifru.ifru_flags;
	flags &= (~bit);	
	ifreq.ifr_ifru.ifru_flags = flags;
	if (0 > ioctl(if_fd, SIOCSIFFLAGS, &ifreq)) {
		perror("SIOCSIFFALGS ioctl err: ");
		return -1;
	}
	return 0;
}

int32_t OpenInterface()
{
    struct ifreq ifr1;
	struct ifreq ifr2;
    if ((interface.socket1 = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0 ||
		(interface.socket2 = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		DBG("call socket failed! %s", strerror(errno));
		return -1;
    }
	DBG("socket1[%d] socket2[%d]\n", interface.socket1, interface.socket2);
    /*
     * Get device number
     */
    memset(&ifr1, 0, sizeof(struct ifreq));
	memset(&ifr2, 0, sizeof(struct ifreq));
    strncpy(ifr1.ifr_name, (const char *)interface.device1_name, sizeof(ifr1.ifr_name));
	strncpy(ifr2.ifr_name, (const char *)interface.device2_name, sizeof(ifr2.ifr_name));
	DBG("ifr1.name is %s\n", ifr1.ifr_name);
	DBG("ifr2.name is %s\n", ifr2.ifr_name);

    if (ioctl(interface.socket1, SIOCGIFINDEX, &ifr1) < 0 ||
		ioctl(interface.socket2, SIOCGIFINDEX, &ifr2) < 0) {
		DBG("call ioctl failed! %s", strerror(errno));
		return -1;
    }
	
	memset(&interface.sa1, 0, sizeof(interface.sa1));
	interface.sa1.sll_family = AF_PACKET;
    interface.sa1.sll_ifindex = ifr1.ifr_ifindex;
    interface.sa1.sll_protocol = htons(ETH_P_ALL);
	memset(&interface.sa2, 0, sizeof(interface.sa2));
	interface.sa2.sll_family = AF_PACKET;
	interface.sa2.sll_ifindex = ifr2.ifr_ifindex;
	interface.sa2.sll_protocol = htons(ETH_P_ALL);
    /*
     * Bind the socket to the device
     */
    if (bind(interface.socket1, (struct sockaddr *)&interface.sa1, sizeof(struct sockaddr_ll)) < 0 ||
		bind(interface.socket2, (struct sockaddr *)&interface.sa2, sizeof(struct sockaddr_ll)) < 0) {
		DBG("call bind failed! %s", strerror(errno));
		return -1;
    }
	
	ioctl(interface.socket1, SIOCGIFHWADDR, &ifr1);
	ioctl(interface.socket2, SIOCGIFHWADDR, &ifr2);
	memcpy(interface.device1_mac, &ifr1.ifr_hwaddr.sa_data, 6);
	memcpy(interface.device2_mac, &ifr2.ifr_hwaddr.sa_data, 6);
	DBG("device1_mac:");PRINT_BYTES(interface.device1_mac, 6);
	DBG("device2_mac:");PRINT_BYTES(interface.device2_mac, 6);

	get_if_flags(interface.socket1, (char *)interface.device1_name, &interface.socket1_if_flags);
	get_if_flags(interface.socket1, (char *)interface.device2_name, &interface.socket2_if_flags);

	add_if_flags(interface.socket1, (char *)interface.device1_name, IFF_PROMISC);
	add_if_flags(interface.socket1, (char *)interface.device2_name, IFF_PROMISC);
	return 0;
}

int CloseInterface()
{
	set_if_flags(interface.socket1, (char *)interface.device1_name, interface.socket1_if_flags);
	set_if_flags(interface.socket1, (char *)interface.device2_name, interface.socket2_if_flags);
	return 0;
}

#ifdef DEBUG
void PrintTraceInfo(Trace *trace)
{
	Flow *flow = NULL;
	Packet *p = NULL;
	int i = 0;
	int j = 0;
	MSG("------------------- Trace -------------------\n");
	MSG("flow capacity [%d]\n", trace->flow_cap);
	MSG("flow number [%d]\n", trace->flow_num);
	MSG("max sending flow id [%d]\n", trace->max_sending_flow_id);
	MSG("max received flow id1 [%d]\n", trace->max_recv_flow_id1);
	MSG("max received flow id2 [%d]\n", trace->max_recv_flow_id2);
	MSG("total packet number [%d]\n", trace->total_pkt_num);
	MSG("total sent packet number [%d]\n", trace->total_sent_num);
	MSG("total received packet number[%d]\n", trace->total_recv_num);
	for(; i < trace->flow_num; ++i) {
		flow = &trace->flow[i];
		MSG("------------------- Flow [ %d ] -------------------\n", i + 1);
		MSG("packet capacity [%d]\n", flow->pkt_cap);
		MSG("packet number [%d]\n", flow->pkt_num);
		MSG("max sent packet id [%d]\n", flow->max_sent_id);
		MSG("max received packet id1 [%d]\n", flow->max_recv_id1);
		MSG("max received packet id2 [%d]\n", flow->max_recv_id2);
		MSG("sent packet number [%d]\n", flow->sent_num);
		MSG("received packet number [%d]\n", flow->recv_num);
		MSG("received packet map:\n");
		PRINT_BYTES(flow->recv_flag, flow->pkt_num);
		printf("my_file.version = %d\n", my_file.pcap_version);
		if (my_file.pcap_version == 4) {
			MSG("addr1 [%s]\n", inet_ntoa(*(struct in_addr *)(&flow->sv4)));
			MSG("addr2 [%s]\n", inet_ntoa(*(struct in_addr *)(&flow->dv4)));
		} else {
			uint8_t addr[46];
			MSG("addr1 [%s]\n", inet_ntop(AF_INET6, flow->sv6, (char *)addr, 46));
			MSG("addr2 [%s]\n", inet_ntop(AF_INET6, flow->dv6, (char *)addr, 46));
		}
		for(j = 0; j < flow->pkt_num; ++j) {
			p = &flow->pkt[j];
			MSG("------------------- Packet [ %d ] -------------------\n", p->id);
			MSG("send interface [%s]\n", p->interface == 1 ? interface.device1_name : interface.device2_name);
			MSG("send time sec[%u] usec[%u]\n", p->sec, p->usec);
			MSG("buffer len [%d]\n", p->len);
			PRINT_BYTES(p->buf, p->len);
		}
	}
}
#endif
int32_t FindFlowByAddr(Trace *trace, ip_addr_t saddr, ip_addr_t daddr)
{
	int index = 0;
	Flow *flow = NULL;
	if (my_file.pcap_version == 4) {
		while (index < trace->flow_num) {
			flow = &trace->flow[index];
			if ((flow->sv4 == saddr.ipv4 && flow->dv4 == daddr.ipv4) ||
				(flow->sv4 == daddr.ipv4 && flow->dv4 == saddr.ipv4)) {
				return index;
			}
			++index;
		}
	} else {
		while (index < trace->flow_num) {
			flow = &trace->flow[index];
			if ((!memcmp(flow->sv6, saddr.ipv6, 16) && !memcmp(flow->dv6, daddr.ipv6, 16)) ||
				(!memcmp(flow->sv6, daddr.ipv6, 16) && !memcmp(flow->dv6, saddr.ipv6, 16))) {
				return index;
			}
			++index;
		}
	}
	return -1;
}

Flow *CreateNewFlow(Trace *trace, ip_addr_t saddr, ip_addr_t daddr)
{
	assert(trace);

	int index = 0;
	Flow *flow = NULL;

	if (trace->flow_cap == 0) {
		trace->flow_cap = 16;
		trace->flow = calloc(16, sizeof(Flow));
	} else if(trace->flow_num == trace->flow_cap) {
		trace->flow_cap += 16;
		trace->flow = realloc(trace->flow, (trace->flow_cap) * sizeof(Flow));
	}
	index = trace->flow_num;
	flow = &trace->flow[index];
	memset(flow, 0, sizeof(Flow));
	
	flow->max_recv_id1 = -1;
	flow->max_recv_id2 = -1;
	flow->max_sent_id = -1;
	memcpy(&flow->src, &saddr, 16);
	memcpy(&flow->dst, &daddr, 16); 	
	trace->flow_num++;
	return flow;
}

void makeup_v4_to_v6(struct iphdr *iph, struct ip6_hdr *iph6)
{
	struct ether_header *ph = (struct ether_header *)(((uint8_t *)iph6) - ETH_HLEN);
	int hlen = (iph->ihl << 2);
	int plen = ntohs(iph->tot_len) - hlen;
	if (plen < 0) {
		return;
	}
	iph6->ip6_flow = htonl(0x60000000);
	iph6->ip6_plen = htons(plen);
	iph6->ip6_nxt = iph->protocol;
	iph6->ip6_hlim = iph->ttl;
	
	ph->ether_type = htons(ETH_P_IPV6);

	memcpy((char *)iph6 + 40, (char *)iph + hlen, plen);
}

void LoadPacket_v4 (const struct pcap_pkthdr *pcap_hdr, Trace *trace, Flow *flow, 
	const u_char *data)
{
    Packet *pkt = NULL;
	struct ether_header *ph = NULL;
    struct iphdr *iph = NULL;
    struct ip6_hdr *ip6h = NULL;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	int offset;
	
	//printf("load packet len %d\n", pcap_hdr->caplen);
	
	if (flow->pkt_cap == 0) {
    	flow->pkt_cap = 128;
		flow->pkt = calloc(128, sizeof(Packet));
    } else if (flow->pkt_num == flow->pkt_cap) {
    	flow->pkt_cap += 128;
		flow->pkt = realloc(flow->pkt, (flow->pkt_cap) * sizeof(Packet));
    }
    pkt = &flow->pkt[flow->pkt_num]; 

	iph = (struct iphdr *)(data + ETH_HLEN);
	offset = (iph->ihl << 2) + ETH_HLEN;
	if (iph->protocol == IPPROTO_TCP) {
		tcph = (struct tcphdr *)(data + offset);
		if (my_file.port && htons(my_file.port) != tcph->th_dport && htons(my_file.port) != tcph->th_sport) {
			return;
		}
	} else if (iph->protocol == IPPROTO_UDP) {
		udph = (struct udphdr *)(data + offset);
		if (my_file.port && htons(my_file.port) != udph->uh_dport && htons(my_file.port) != udph->uh_sport) {
			return;
		}
	}

	if (!my_file.v4tov6) {
		pkt->len = pcap_hdr->caplen;
	    pkt->buf = malloc(pkt->len + ETHER_CRC_LEN);
	    memcpy(pkt->buf, data, pkt->len);
		iph = (struct iphdr *)(pkt->buf + ETH_HLEN);
		
		if (iph->saddr == flow->sv4) {
			pkt->interface = 1;
		} else {
			pkt->interface = 2;
		}
		
		if (my_file.alter_ip) {
			if (pkt->interface == 1) {
				if (my_file.device2_in_nat) {
					iph->saddr = interface.sv4;
					iph->daddr = interface.device2nat4;
				} else {
					iph->saddr = interface.sv4;
					iph->daddr = interface.dv4;
				}
			} else {
				if (my_file.device1_in_nat) {
					iph->daddr = interface.device1nat4;
					iph->saddr = interface.dv4;
				} else {
					iph->daddr = interface.sv4;
					iph->saddr = interface.dv4;
				}
			}
		}
		
		ip_csum(iph);
		if ((iph->frag_off & htons(0x1fff)) == 0) {
			if (iph->protocol == IPPROTO_TCP) {
				tcph = (struct tcphdr *)(pkt->buf + offset);
				tcp_csum(iph, (uint8_t *)tcph);
			} else if (iph->protocol == IPPROTO_UDP) {
				udph = (struct udphdr *)(pkt->buf + offset);
				if (udph->uh_sum != 0) {
					udp_csum(iph, (uint8_t *)udph);
				}
			}
		}
	} else {
		pkt->len = pcap_hdr->caplen + 20;
	    pkt->buf = malloc(pkt->len + ETHER_CRC_LEN);
  	    memcpy(pkt->buf, data, ETH_HLEN);
  	    ip6h = (struct ip6_hdr *)(pkt->buf + ETH_HLEN);
  	    makeup_v4_to_v6(iph, ip6h);
  		if (iph->saddr == flow->sv4) {
			memcpy(&ip6h->ip6_src, interface.device1_4to6.ipv6, 16);
			memcpy(&ip6h->ip6_dst, interface.device2_4to6.ipv6, 16);
			pkt->interface = 1;
  		} else {
			memcpy(&ip6h->ip6_src, interface.device2_4to6.ipv6, 16);
			memcpy(&ip6h->ip6_dst, interface.device1_4to6.ipv6, 16);
			pkt->interface = 2;
  		}
		offset = 40 + ETH_HLEN;
		if (ip6h->ip6_nxt == IPPROTO_TCP) {
			tcp_csum6(ip6h, pkt->buf + offset);
		} else if (ip6h->ip6_nxt == IPPROTO_UDP) {
			udp_csum6(ip6h, pkt->buf + offset);
		}
	}
	pkt->payload_offset = offset;
    /*
     * Rewrite the mac addresses on the packet.
     */
    if (my_file.alter_mac) {
	    ph = (struct ether_header *)pkt->buf;
		if (pkt->interface == 1) {
			ph->ether_shost[0] = interface.device1_mac[0];
			ph->ether_shost[1] = interface.device1_mac[1];
			ph->ether_shost[2] = interface.device1_mac[2];
			ph->ether_shost[3] = interface.device1_mac[3];
			ph->ether_shost[4] = interface.device1_mac[4];
			ph->ether_shost[5] = interface.device1_mac[5];
			
			ph->ether_dhost[0] = interface.fw_mac1[0];
			ph->ether_dhost[1] = interface.fw_mac1[1];
			ph->ether_dhost[2] = interface.fw_mac1[2];
			ph->ether_dhost[3] = interface.fw_mac1[3];
			ph->ether_dhost[4] = interface.fw_mac1[4];
			ph->ether_dhost[5] = interface.fw_mac1[5];
		} else {
			ph->ether_dhost[0] = interface.fw_mac2[0];
			ph->ether_dhost[1] = interface.fw_mac2[1];
			ph->ether_dhost[2] = interface.fw_mac2[2];
			ph->ether_dhost[3] = interface.fw_mac2[3];
			ph->ether_dhost[4] = interface.fw_mac2[4];
			ph->ether_dhost[5] = interface.fw_mac2[5];
			
			ph->ether_shost[0] = interface.device2_mac[0];
			ph->ether_shost[1] = interface.device2_mac[1];
			ph->ether_shost[2] = interface.device2_mac[2];
			ph->ether_shost[3] = interface.device2_mac[3];
			ph->ether_shost[4] = interface.device2_mac[4];
			ph->ether_shost[5] = interface.device2_mac[5];
		} 
	}
    /* Compute the FCS on the Ethernet Frame
     * Some people say the hardare should do this, but it does not seem to.
     * Also for packets > 1510, the WriteInterface dies with a message too long error
     */
    /*
     * This section actually calculates the FCS, but it's not currently
     * working correctly, so I've commented it out.  The CRC32 function
     * needs to be verified.
     */
	/*
   if ( pkt->len <= 15 + ETH_HLEN ) {
		uint32_t newFCS = CRC32( pkt->buf , pkt->len );
		memcpy(pkt->buf + pkt->len , &newFCS , ETHER_CRC_LEN);
    }
    */
    pkt->id = trace->total_pkt_num++;
    flow->pkt_num++;
}

void LoadPacket_v6(const struct pcap_pkthdr *pcap_hdr, Trace *trace, Flow *flow, 
	const u_char * data)
{
    Packet *pkt = NULL;
	struct ether_header *ph = NULL;
	struct ip6_hdr *iph6 = NULL;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	int offset;
	
	//printf("load packet len %d\n", pcap_hdr->caplen);
	if (flow->pkt_cap == 0) {
    	flow->pkt_cap = 128;
		flow->pkt = calloc(128, sizeof(Packet));
    } else if (flow->pkt_num == flow->pkt_cap) {
    	flow->pkt_cap += 128;
		flow->pkt = realloc(flow->pkt, (flow->pkt_cap) * sizeof(Packet));
    }
    pkt = &flow->pkt[flow->pkt_num]; 
	
	iph6 = (struct ip6_hdr *)(data + ETH_HLEN);
	offset = 40 + ETH_HLEN;
	
	if (iph6->ip6_nxt == IPPROTO_TCP) {
		tcph = (struct tcphdr *)(data + offset);
		if (my_file.port && htons(my_file.port) != tcph->th_dport && htons(my_file.port) != tcph->th_sport) {
			return;
		}
	} else if (iph6->ip6_nxt == IPPROTO_UDP) {
		udph = (struct udphdr *)(data + offset);
		if (my_file.port && htons(my_file.port) != udph->uh_dport && htons(my_file.port) != udph->uh_sport) {
			return;
		}
	}

	pkt->len = pcap_hdr->caplen;
    pkt->buf = malloc(pkt->len + ETHER_CRC_LEN);
    memcpy(pkt->buf, data, pkt->len);
	iph6 = (struct ip6_hdr *)(pkt->buf + ETH_HLEN);

	if (!memcmp(&iph6->ip6_src, flow->sv6, 16)) {
		pkt->interface = 1;
	} else {
		pkt->interface = 2;
	}

	if (my_file.alter_ip) {
		if (pkt->interface == 1) {
			if (my_file.device2_in_nat) {
				memcpy(&iph6->ip6_src, interface.sv6, 16);
				memcpy(&iph6->ip6_dst, interface.device2nat6, 16);	
			} else {
				memcpy(&iph6->ip6_src, interface.sv6, 16);
				memcpy(&iph6->ip6_dst, interface.dv6, 16);
			}
			pkt->interface = 1;
		} else {
			if (my_file.device1_in_nat) {
				memcpy(&iph6->ip6_src, interface.device1nat6, 16);
				memcpy(&iph6->ip6_dst, interface.sv6, 16);
			} else {
				memcpy(&iph6->ip6_src, interface.dv6, 16);
				memcpy(&iph6->ip6_dst, interface.sv6, 16);
			}
			pkt->interface = 2;
		}
	}

	offset = 40 + ETH_HLEN;
	if (iph6->ip6_nxt == IPPROTO_TCP) {
		tcp_csum6(iph6, pkt->buf + offset);
	} else if (iph6->ip6_nxt == IPPROTO_UDP) {
		udp_csum6(iph6, pkt->buf + offset);
	}
	pkt->payload_offset = offset;
    /*
     * Rewrite the mac addresses on the packet.
     */
    if (my_file.alter_mac) {
	    ph = (struct ether_header *)pkt->buf;
		if (pkt->interface == 1) {
			ph->ether_shost[0] = interface.device1_mac[0];
			ph->ether_shost[1] = interface.device1_mac[1];
			ph->ether_shost[2] = interface.device1_mac[2];
			ph->ether_shost[3] = interface.device1_mac[3];
			ph->ether_shost[4] = interface.device1_mac[4];
			ph->ether_shost[5] = interface.device1_mac[5];
			
			ph->ether_dhost[0] = interface.fw_mac1[0];
			ph->ether_dhost[1] = interface.fw_mac1[1];
			ph->ether_dhost[2] = interface.fw_mac1[2];
			ph->ether_dhost[3] = interface.fw_mac1[3];
			ph->ether_dhost[4] = interface.fw_mac1[4];
			ph->ether_dhost[5] = interface.fw_mac1[5];
		} else {
			ph->ether_dhost[0] = interface.fw_mac2[0];
			ph->ether_dhost[1] = interface.fw_mac2[1];
			ph->ether_dhost[2] = interface.fw_mac2[2];
			ph->ether_dhost[3] = interface.fw_mac2[3];
			ph->ether_dhost[4] = interface.fw_mac2[4];
			ph->ether_dhost[5] = interface.fw_mac2[5];
			
			ph->ether_shost[0] = interface.device2_mac[0];
			ph->ether_shost[1] = interface.device2_mac[1];
			ph->ether_shost[2] = interface.device2_mac[2];
			ph->ether_shost[3] = interface.device2_mac[3];
			ph->ether_shost[4] = interface.device2_mac[4];
			ph->ether_shost[5] = interface.device2_mac[5];
		}
	}
    /* Compute the FCS on the Ethernet Frame
     * Some people say the hardare should do this, but it does not seem to.
     * Also for packets > 1510, the WriteInterface dies with a message too long error
     */
    /*
     * This section actually calculates the FCS, but it's not currently
     * working correctly, so I've commented it out.  The CRC32 function
     * needs to be verified.
     */
	/*
   if ( pkt->len <= 15 + ETH_HLEN ) {
		uint32_t newFCS = CRC32( pkt->buf , pkt->len );
		memcpy(pkt->buf + pkt->len , &newFCS , ETHER_CRC_LEN);
    }
    */
    
    pkt->id = trace->total_pkt_num++;
    flow->pkt_num++;
}

void LoadFlow(u_char *user, const struct pcap_pkthdr *pcap_hdr, const u_char *data)
{
	Trace *trace = (Trace *)user;
	Flow *flow = NULL;
	struct ether_header *eth = NULL;
	struct iphdr *iph = NULL;
	struct ip6_hdr *iph6 = NULL;
		
	ip_addr_t saddr;
	ip_addr_t daddr;
	int32_t ret = 0;
	
	eth = (struct ether_header *)data;
	if (my_file.pcap_version == 4) {
		if(eth->ether_type != htons(ETH_P_IP))
			return;
		iph = (struct iphdr *)(data + ETH_HLEN);
		saddr.ipv4 = iph->saddr;
		daddr.ipv4 = iph->daddr;
	} else {
		if (eth->ether_type != htons(ETH_P_IPV6))
			return;
		iph6 = (struct ip6_hdr *)(data + ETH_HLEN);
		memcpy(saddr.ipv6, &iph6->ip6_src, 16);
		memcpy(daddr.ipv6, &iph6->ip6_dst, 16);
	}

	ret = FindFlowByAddr(trace, saddr, daddr);
	if (ret == -1) {
		flow = CreateNewFlow(trace, saddr, daddr);
	} else {
		flow = &trace->flow[ret];
	}
	my_file.LoadPacket(pcap_hdr, trace, flow, data);
}

Trace *LoadTrace(uint8_t *name)
{
    pcap_t *in_file = NULL;
    Trace *trace = NULL;
    char ebuf[256];
	int index = -1;
	Flow *flow = NULL;
	
    if (!(in_file = pcap_open_offline((const char *)name, ebuf))) {
    	DBG("call pcap_open_offline %s failed! %s\n", name, ebuf);
		return NULL;
	}
    
    trace = (Trace *)calloc(sizeof(Trace), 1);
	trace->max_sending_flow_id = 0;
	trace->max_recv_flow_id1 = -1;
	trace->max_recv_flow_id2 = -1;
	
    if (pcap_dispatch(in_file, -1, (void *)&LoadFlow,(u_char *)trace) < 0) {
    	DBG("call pcap_dispatch failed!\n");
		return NULL;
    }
    pcap_close(in_file);

    /*
     * Exit if there are no packets in the file that we could replay
     */
    if (trace->total_pkt_num == 0) {
    	DBG("%s is empty\n", name);
	//	return NULL;
    }
    
    for(index = 0; index < trace->flow_num; ++index) {
    	flow = &trace->flow[index];
    	flow->recv_flag = (int8_t *)calloc(flow->pkt_num, sizeof(int32_t));
    }
    
    return trace;
}

int ether_check_v6(void *addr, int len, int dir)
{
	struct ether_header *ph = (struct ether_header *)addr;
	char *buffer = (char *)addr;
	
	if (len < ETH_HLEN + 20) {
		return 1;
	}
	if (ph->ether_type != htons(ETH_P_IPV6)) {
		return 1;
	}
    if (dir == 1) {
		if (memcmp(interface.fw_mac1, buffer + 6, 6) || memcmp(interface.device1_mac, buffer, 6)) {
			DBG("->mac not match, return\n");
			return 1;
		} 
	} else {
		if (memcmp(interface.fw_mac2, buffer + 6, 6) || memcmp(interface.device2_mac, buffer, 6)) {
			DBG("->mac not match, return\n");
			return 1;
		}
	}
	return 0;
}

int ether_check_v4(void *addr, int len, int dir)
{
	struct ether_header *ph = (struct ether_header *)addr;
	char *buffer = (char *)addr;
	
	if (len < ETH_HLEN + 40) {
		return 1;
	}
	if (ph->ether_type != htons(ETH_P_IP)) {
		return 1;
	}
	
	if (my_file.alter_mac) {
    if (dir == 1) {
		if (memcmp(interface.fw_mac1, buffer + 6, 6) || memcmp(interface.device1_mac, buffer, 6)) {
			DBG("->mac not match, return\n");
			return 1;
		} 
	} else {
		if (memcmp(interface.fw_mac2, buffer + 6, 6) || memcmp(interface.device2_mac, buffer, 6)) {
			DBG("->mac not match, return\n");
			return 1;
		}
	}
	}
	return 0;
}

int ip_check_v4(void *addr, int len, int dir, int *offset)
{
	struct iphdr *iph = (struct iphdr *)addr;
	
	if (my_file.alter_ip) {
		if (dir == 1) {
			if (iph->saddr != interface.dv4 || iph->daddr != interface.sv4) {
				DBG("->pkt saddr/daddr not match, return\n");
				return 1;
			}
		} else {
			if (iph->saddr != interface.sv4 || iph->daddr != interface.dv4) {
				DBG("->pkt saddr/daddr not match, return\n");
				return 1;
			}
		}
	}
	*offset = (iph->ihl << 2) + ETH_HLEN;
	return 0;
}

int ip_check_v6(void *addr, int len, int dir, int *offset)
{
	struct ip6_hdr *iph6 = (struct ip6_hdr *)addr;
	
	if (my_file.v4tov6) {
		if (dir == 1) {
			if (memcmp(&iph6->ip6_src, interface.device2_4to6.ipv6, 16) || memcmp(&iph6->ip6_dst, interface.device1_4to6.ipv6, 16)) {
				DBG("->pkt saddr/daddr not match, return\n");
				return 1;
			}
		} else {
			if (memcmp(&iph6->ip6_src, interface.device1_4to6.ipv6, 16) || memcmp(&iph6->ip6_dst, interface.device2_4to6.ipv6, 16)) {
				DBG("->pkt saddr/daddr not match, return\n");
				return 1;
			}
		}
		goto out;
	}
	
	if (my_file.alter_ip) {
		if (dir == 1) {
			if (memcmp(&iph6->ip6_src, interface.dv6, 16) || memcmp(&iph6->ip6_dst, interface.sv6, 16)) {
				DBG("->pkt saddr/daddr not match, return\n");
				return 1;
			}
		} else {
			if (memcmp(&iph6->ip6_src, interface.sv6, 16) || memcmp(&iph6->ip6_dst, interface.dv6, 16)) {
				DBG("->pkt saddr/daddr not match, return\n");
				return 1;
			}
		}
	}
out:
	*offset = 40 + ETH_HLEN;
	return 0;
}

void ReadFlowPacket(Flow *flow, uint32_t dir)
{
	int cmp_id = -1;
	int offset = 0;
    int recv_len = 0;
    static u_char buffer[4096];
	int flags = 0;
	Packet *p = NULL;
	
	int socket = -1;
	if (dir == 1) {
		socket = interface.socket1;
	} else{
		socket = interface.socket2;
	}

    flags = fcntl(socket, F_GETFL);
    fcntl(socket, F_SETFL, O_NONBLOCK);
	if ((recv_len = recvfrom(socket, buffer, sizeof(buffer), MSG_TRUNC, NULL, NULL)) < 0) {
		DBG("call recvfrom failed! %s\n", strerror(errno));
		fcntl(socket, F_SETFL, flags);
		return;
	}
    fcntl(socket, F_SETFL, flags);

	DBG("Recv len %d\n", recv_len);
	if (my_file.Recv_L2_Check(buffer, recv_len, dir)) {
		return;
	}
	
	if (my_file.Recv_L3_Check(buffer + ETH_HLEN, recv_len - ETH_HLEN, dir, &offset)) {
		return;
	}
	
    if (dir == 1) {
		cmp_id = flow->max_recv_id2 + 1;
	} else {
		cmp_id = flow->max_recv_id1 + 1;
	}
	DBG("Just sent %d, compare from %d\n", flow->max_sent_id + 1, cmp_id + 1);
	while (cmp_id <= flow->max_sent_id) {
		if (flow->pkt[cmp_id].interface != dir) {
			p = &flow->pkt[cmp_id];
			if (!memcmp(p->buf + p->payload_offset, buffer + offset, min(p->len, recv_len) - offset)) {
				if (dir == 1) {
					flow->max_recv_id2 = cmp_id;
				} else {
					flow->max_recv_id1 = cmp_id;
				}
				flow->recv_num++;
				flow->recv_flag[cmp_id] = 1;
				
				DBG(" ^_^ Match pkt %d\n", p->id);
				MSG("---------------Recv pkt %d\n", p->id);
				break;
			}
		}
		++cmp_id;
	}
}
	
void ReadTracePacket(Trace * trace, uint32_t dir)
{
	int cmp_id  =-1;
	int cmp_flow = -1;
	Flow *flow = NULL;

    int recv_len = 0;
    static u_char buffer[4096];
	int flags = 0;
	Packet *p = NULL;
	int socket = -1;
	int offset = 0;

	if (dir == 1) {
		socket = interface.socket1;
	} else {
		socket = interface.socket2;
	}
	flags = fcntl(socket, F_GETFL);
    fcntl(socket, F_SETFL, O_NONBLOCK);
	if ((recv_len = recvfrom(socket, buffer, sizeof(buffer), MSG_TRUNC, NULL, NULL)) < 0) {
		DBG("call recvfrom failed! %s\n", strerror(errno));
		fcntl(socket, F_SETFL, flags);
		return;
	}
	fcntl(socket, F_SETFL, flags);

	DBG("Recv len %d\n", recv_len);
	if (my_file.Recv_L2_Check(buffer, recv_len, dir)) {
		return;
	}

	if (my_file.Recv_L3_Check(buffer + ETH_HLEN, recv_len - ETH_HLEN, dir, &offset)) {
		return;
	}
	
    if (dir == 1) {
		cmp_flow = trace->max_recv_flow_id2 + 1;
		flow = &trace->flow[cmp_flow];
		cmp_id = flow->max_recv_id2 + 1;
	} else {
		cmp_flow = trace->max_recv_flow_id1 + 1;
		flow = &trace->flow[cmp_flow];
		cmp_id = flow->max_recv_id1 + 1;
	}
	
	DBG("Just sent flow %d pkt %d ,compare from flow %d pkt %d\n", 
			trace->max_sending_flow_id, trace->flow[trace->max_sending_flow_id].max_sent_id,
			cmp_flow, cmp_id);
	for (;;) {
		DBG("CMP ID %d cmp flwo %d flow->max_send_id %d\n", cmp_id, cmp_flow, flow->max_sent_id);
		if (cmp_flow == trace->max_sending_flow_id) {
			if(cmp_id > flow->max_sent_id) {
				break;
			} else {
				p = &flow->pkt[cmp_id];
				if (p->interface != dir) {
					if (!memcmp(p->buf + p->payload_offset, buffer + offset, min(p->len, recv_len) - offset)) {
						if (dir == 1) {
							flow->max_recv_id2 = cmp_id;
							if (cmp_id == flow->pkt_num - 1) {
								trace->max_recv_flow_id2 = cmp_flow;
							}
						} else {
							flow->max_recv_id1 = cmp_id;
							if (cmp_id == flow->pkt_num - 1) {
								trace->max_recv_flow_id1 = cmp_flow;
							}
						}
						flow->recv_num++;
						flow->recv_flag[cmp_id] = 1;
						trace->total_recv_num++;
						DBG("^_^ Match flow %d pkt %d\n", cmp_flow + 1, cmp_id + 1);
						MSG("---------------Recv pkt %d\n", p->id);
						break;
					}
				} 
				cmp_id++;
			}
		} else {
			flow = &trace->flow[cmp_flow];
			if (cmp_id > flow->max_sent_id) {
				cmp_flow++;
				flow = &trace->flow[cmp_flow];
				cmp_id = 0;
			} else {
				p = &flow->pkt[cmp_id];
				if (p->interface != dir) {
					if (!memcmp(p->buf + p->payload_offset, buffer + offset, min(p->len, recv_len) - offset)) {
						if (dir == 1) {
							flow->max_recv_id2 = cmp_id;
							if (cmp_id == flow->pkt_num - 1) {
								trace->max_recv_flow_id2 = cmp_flow;
							}
						} else {
							flow->max_recv_id1 = cmp_id;
							if (cmp_id == flow->pkt_num - 1) {
								trace->max_recv_flow_id1 = cmp_flow;
							}
						}
						flow->recv_num++;
						flow->recv_flag[cmp_id] = 1;
						trace->total_recv_num++;
						DBG("^_^ Match flow %d pkt %d\n", cmp_flow + 1, cmp_id + 1);
						MSG("---------------Recv pkt %d\n", p->id);
						break;
					}
				} 
				cmp_id++;
			}
		}
	}
}

void SendFlow(Flow *flow)
{
	int send_id = flow->max_sent_id +1;
	Packet *p = &flow->pkt[send_id];
	
	struct timeval starttime;
	
	gettimeofday(&starttime, NULL);
	p->sec = starttime.tv_sec;
	p->usec = starttime.tv_usec;
	if (p->interface == 1) {
		if (sendto(interface.socket1, p->buf, p->len, 0, (struct sockaddr *)NULL, 0) < 0) {
			MSG("eth call sendto failed! %s\n", strerror(errno));
			return;
		}
		DBG("Send %d bytes from %s\n", p->len, interface.device1_name);
	} else {
		if (sendto(interface.socket2, p->buf, p->len, 0, (struct sockaddr *)NULL, 0) < 0) {
			MSG("eth call sendto failed! %s\n", strerror(errno));
			return;
		}
		DBG("Send %d bytes from %s\n", p->len, interface.device2_name);
	}
	flow->max_sent_id++;
	flow->sent_num++;
	
	MSG("Send pkt %d\n", p->id);
}

void SendTrace(Trace *trace)
{
	int flow_id = trace->max_sending_flow_id;
	Flow *flow = &trace->flow[flow_id];
	if (flow->sent_num == flow->pkt_num) {
		trace->max_sending_flow_id++;
		flow++;
	}
	int send_id = flow->max_sent_id + 1;
	Packet *p = &flow->pkt[send_id];
	
	struct timeval starttime;
	
	gettimeofday(&starttime, NULL);
	p->sec = starttime.tv_sec;
	p->usec = starttime.tv_usec;
	if (p->interface == 1) {
		if (sendto(interface.socket1, p->buf, p->len, 0, (struct sockaddr *)NULL, 0) < 0) {
			MSG("eth1 call sendto failed! %s\n", strerror(errno));
			return;
		}
		DBG("Send %d bytes from %s\n", p->len, interface.device1_name);
	} else {
		if (sendto(interface.socket2, p->buf, p->len, 0, (struct sockaddr *)NULL, 0) < 0) {
			MSG("eth2 call sendto failed! %s\n", strerror(errno));
			return;
		}
		DBG("Send %d bytes from %s\n", p->len, interface.device2_name);
	}
	flow->max_sent_id++;
	flow->sent_num++;
	trace->total_sent_num++;
	
	MSG("Send pkt %d\n", p->id);
}

void RecvFlow(Flow *flow)
{
	int numFds = 0;
    static int maxFd = 0;
    static fd_set readFds;
    struct timeval timeout;
    struct timeval zeroTimeout;
	
	uint32_t dt = 0;
	time_t start_sec = flow->pkt[flow->max_sent_id].sec;
	long start_usec = flow->pkt[flow->max_sent_id].usec;
	
	maxFd = interface.socket2 > interface.socket1 ? interface.socket2 : interface.socket1;
	zeroTimeout.tv_sec = 0;
	zeroTimeout.tv_usec = 0;

	FD_ZERO(&readFds);
	FD_SET(interface.socket1, &readFds);
	FD_SET(interface.socket2, &readFds);
	for (;;) {
		numFds = select(maxFd + 1, &readFds, NULL, NULL, &zeroTimeout);		
		if (numFds > 0) {
			DBG("Read notice, queue number[%d]\n", numFds);
			if (FD_ISSET(interface.socket1, &readFds)) {
				ReadFlowPacket(flow, 1);
			} else if(FD_ISSET(interface.socket2, &readFds)) {
				ReadFlowPacket(flow, 2);
			}
		}
		gettimeofday(&timeout, NULL);
		dt = (timeout.tv_sec - start_sec) * 1000 + (timeout.tv_usec - start_usec) / 1000;
		if (dt > my_file.timeout) {
			DBG("RecvPacket timeout return\n");
			return;
		}	
	}
	
}

void RecvTrace(Trace *trace)
{
    int numFds = 0;
    static int maxFd = 0;
    static fd_set readFds;
    struct timeval timeout;
    struct timeval zeroTimeout;
	int flow_id = -1;
	Flow *flow = NULL;
	
	flow_id = trace->max_sending_flow_id;
	flow = &trace->flow[flow_id];
	
	uint32_t dt = 0;
	time_t start_sec = flow->pkt[flow->max_sent_id].sec;
	uint32_t start_usec = flow->pkt[flow->max_sent_id].usec;
	
	maxFd = interface.socket2 > interface.socket1 ? interface.socket2 : interface.socket1;
	zeroTimeout.tv_sec = 0;
	zeroTimeout.tv_usec = 0;

	FD_ZERO(&readFds);
	FD_SET(interface.socket1, &readFds);
	FD_SET(interface.socket2, &readFds);
	for (;;) {
		numFds = select(maxFd + 1, &readFds, NULL, NULL, &zeroTimeout);		
		if(numFds > 0) {
			DBG("Read notice, queue number[%d]\n", numFds);
			if (FD_ISSET(interface.socket1, &readFds)) {
				ReadTracePacket(trace, 1);
			} else if(FD_ISSET(interface.socket2, &readFds)) {
				ReadTracePacket(trace, 2);
			}
		}
		gettimeofday(&timeout, NULL);
		dt = (timeout.tv_sec - start_sec) * 1000 + (timeout.tv_usec - start_usec) / 1000;
		if (dt > my_file.timeout) {
			DBG("RecvPacket timeout return\n");
			return;
		}	
	}
}

Flow *FindMaxFlow(Trace *trace)
{
	int flow_id;
	int pktnum = 0;
	Flow *flow = NULL;
	for(flow_id = 0; flow_id < trace->flow_num; flow_id++) {
		if(trace->flow[flow_id].pkt_num > pktnum) {
			flow = &trace->flow[flow_id];
			pktnum = flow->pkt_num;
		}
	}
	return flow;
}

void handleInterrupt(int arg)
{
	EXIT("%s: Interrupted! Sent: %d  Recv: %d\n", my_file.name, t->total_sent_num, t->total_recv_num);
}
void handleSegv(int arg)
{
	EXIT("%s: Seg Fault! Sent: %d  Recv: %d\n", my_file.name, t->total_sent_num, t->total_recv_num);
}

int main(int argc, char *argv[])
{
	system("rm -f ./log.txt ./commond_end");

	int arg;
    extern char *optarg;
    int8_t ch = 0; 
    Trace *trace = NULL;
#define DEF_INTERVAL 20
	memset(&my_file, 0, sizeof(my_file));
	my_file.timeout = DEF_INTERVAL;
	my_file.retrans = 1;
	my_file.loops = 1;
	my_file.pcap_version = 4;
	my_file.send_version = 4;
	my_file.recv_version = 4;
	my_file.mis = 0;
	my_file.v4tov6 = 0;
	my_file.alter_ip = 1;
	my_file.alter_mac = 1;
	my_file.name = NULL;
	my_file.port = 0;
	my_file.device1_in_nat = 0;
	my_file.device2_in_nat = 0;
	
	Flow *flow = NULL;
	int flow_id = -1;
	int pkt_id = -1;

    while ((ch = getopt(argc, argv, "l:t:f:r:mv:p:c:2:3:")) != -1) {
      	switch (ch) {
			case '2':
				my_file.alter_mac = atoi(optarg);
				break;
			case '3':
				my_file.alter_ip = atoi(optarg);
				break;
			case 'c':
				arg = atoi(optarg);
				if (arg == 46) {
					my_file.v4tov6 = 1;
				} else {
					EXIT("Illega argument for -c %d\n", arg);
				}
				break;
      		case 'm':
      			my_file.mis = 1;
      			break;
      		case 'l':
      			my_file.loops = atoi(optarg);
      			break;
      		case 'r':
      			my_file.retrans = atoi(optarg);
      			break;
			case 't':
		    	my_file.timeout = atoi(optarg);
		    	break;
			case 'p':
				my_file.port = atoi(optarg);
				break;
			case 'f':
		    	my_file.name = (uint8_t *)optarg;
		    	break;
			case 'v':
				my_file.pcap_version = atoi(optarg);
				if (my_file.pcap_version != 4 && my_file.pcap_version != 6) {
					EXIT("-v param error(4/6)\n");
				}
				break;
			default:
				EXIT("illegal argument -%c\n", ch);
      	}
    }

	if (my_file.v4tov6) {
		if (my_file.pcap_version != 4) {
			EXIT("When use -c 46, you must also use -v 4 to tell me the original packet is ipv4\n");
		}
		my_file.send_version = 6;
		my_file.recv_version = 6;
	}

	if (my_file.pcap_version == 4) {
		my_file.LoadPacket = LoadPacket_v4;
	} else {
		my_file.LoadPacket = LoadPacket_v6;
	}

	if (my_file.recv_version == 4) {
		my_file.Recv_L3_Check = ip_check_v4;
		my_file.Recv_L2_Check = ether_check_v4;
	} else {
		my_file.Recv_L3_Check = ip_check_v6;
		my_file.Recv_L2_Check = ether_check_v6;
	}
	
	if (!my_file.name) {
		EXIT("need -f argument\n");
	}
	signal(SIGINT, handleInterrupt);
  	signal(SIGSEGV, handleSegv);

	DBG("filename:%s loop:%d retrans:%d timeout:%d mis:%d\n", 
		my_file.name, my_file.loops, my_file.retrans, my_file.timeout, my_file.mis);

	MSG("| -------- Begin Replay %s --------- |\n", my_file.name);
	
    if (get_interface_info("conf") < 0)
		EXIT("get_interface_info failed!\n");
	
    if (OpenInterface() < 0)
		EXIT("OpenInterface failed!\n");

	
	if (!(trace = LoadTrace(my_file.name)))
		EXIT("LoadTrace failed!\n");
#ifdef DEBUG
//	PrintTraceInfo(trace);
#endif
	
	if (my_file.mis) {
		flow_id = 0;
		while (flow_id < trace->flow_num) {
		MSG("----------------------------------------------SEND FLOW %d-----------------------\n", flow_id);
			flow = &trace->flow[flow_id];
			pkt_id = 0;
			if (flow->pkt_num == 0) {
					trace->max_sending_flow_id ++;
			} else {
				while (pkt_id < flow->pkt_num) {
					SendTrace(trace);
					RecvTrace(trace);
					++pkt_id;
				}
				RecvTrace(trace);
			}
			++flow_id;
		}

		if (trace->total_sent_num != trace->total_recv_num) {
			MSG("Loss pkt id: ");
			for (flow_id = 0; flow_id < trace->flow_num; ++flow_id) {
				flow = &trace->flow[flow_id];
				for (pkt_id = 0; pkt_id < flow->pkt_num; ++pkt_id) {
					if (flow->recv_flag[pkt_id] == 0) {
						MSG("%d, ", (flow->pkt[pkt_id]).id);
					}
				}
			}
			MSG("\n");
		}
		MSG("%s: Sent->%d  Recv->%d\n\n", my_file.name, trace->total_sent_num, trace->total_recv_num);
	} else {
		flow = FindMaxFlow(trace);
		pkt_id = 0;
		if (flow && flow->pkt_num > 0) {
			while (pkt_id < flow->pkt_num) {
				SendFlow(flow);
				RecvFlow(flow);
				++pkt_id;
			}		
			RecvFlow(flow);
		}

		if (flow && flow->sent_num != flow->recv_num) {
			MSG("Loss pkt id: ");
		for (pkt_id = 0; flow && pkt_id < flow->pkt_num; ++pkt_id) {
					if (flow->recv_flag[pkt_id] == 0) {
						MSG("%d, ", (flow->pkt[pkt_id]).id);
					}
				}
			MSG("\n");
		}
		printf("%s: Sent->%d  Recv->%d\n\n", my_file.name, flow ? flow->sent_num: 0, flow?flow->recv_num:0);
	}

	CloseInterface();
	return 0;
}
	

