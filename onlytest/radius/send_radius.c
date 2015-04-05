
#include<stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "pcap.h"  
#define PCAP_FILE "eth1.pcap"

#define MAX_ETH_FRAME 1514  

char *buff = NULL;

int readSize =0, ret = 0,i = 0,j = 0;

int main()
{
	pcap_file_header  pfh;  
	pcap_header  ph;  

	FILE *fp = fopen(PCAP_FILE, "rw");  

	if (fp==NULL) {  
		
	    	fprintf(stderr, "Open file %s error.",PCAP_FILE);  
		exit(-1);
	}  
  
    	
	fread(&pfh, sizeof(pcap_file_header), 1, fp);   
	buff = (char *)malloc(MAX_ETH_FRAME); 

	while(1)
	{
		memset(buff,0,MAX_ETH_FRAME);  
	    		
		readSize=fread(&ph, sizeof(pcap_header), 1, fp);  
		if (readSize<=0) 
		{  
			break;  
		}

		if (buff==NULL) 
		{  
			fprintf(stderr, "malloc memory failed.\n");  
			perror("malloc");
			exit(-1);
		}  

		//获取数据包内容
		readSize=fread(buff,1,ph.capture_len, fp);  
		if (readSize != ph.capture_len) {  
			free(buff);  
			fprintf(stderr, "pcap file parse error.\n");
			exit(-1);
		}  

		//获取数据包内容
		readSize=fread(buff,1,ph.capture_len, fp);  
		if (readSize != ph.capture_len) {  
			free(buff);  
			fprintf(stderr, "pcap file parse error.\n");  
			exit(-1);
		} 
//<<============================================================================================<<
		int sock, bytes_send, fromlen,n,id,s;
		struct sockaddr_in toaddr;
		struct iphdr  *ip_send;
		struct udphdr *udp_send;
		//发送地址
		struct in_addr add;

		toaddr.sin_family =AF_INET;

		//建立原始TCP包方式IP+TCP信息包
		sock = socket(AF_INET, SOCK_RAW,IPPROTO_RAW);   //IP方式
		if (sock>0) {printf("socket ok\n");}
		else {printf ("socket error \n");}
		n=1;
		if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n)) < 0) 
		{
			printf("2");
			perror("IP_HDRINCL");
			exit(1);
		}
	
		bytes_send=sendto(sock,buff,1024,0,(struct sockaddr *)&toaddr,sizeof(toaddr));    
		if (bytes_send>0)
		{
			ip_send = (struct iphdr*)buff + sizeof(struct ethhdr);
			udp_send = (struct udphdr*)(buff + sizeof(struct iphdr));

			printf("OK bytes_send %d \n",bytes_send);
			add.s_addr = ip_send->saddr;
			printf("IP_source address ::: %s \n",inet_ntoa(add));
			add.s_addr = ip_send->daddr;
			printf("IP_dest address ::: %s \n",inet_ntoa(add));
			printf("Port_source ::::%d \n", ntohs(udp_send->source));
			printf("Port_dest ::::%d \n", ntohs(udp_send->dest));
	
		}
		else
			perror("sendto");
		printf("发送radius成功\n");
		close(sock);
	}
}
