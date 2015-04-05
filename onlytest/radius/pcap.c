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
#define ERROR_FILE_OPEN_FAILED -1  
#define ERROR_MEM_ALLOC_FAILED -2  
#define ERROR_PCAP_PARSE_FAILED -3  
       
//radius协议信息
struct radiushdr
{
	/* code段，占用两个字节 */
	unsigned char code;			
	/* 标识段，占用一个字节 */
	unsigned char identifier;		
	/* 长度字段，占用两个字节 */
	short length;						
	/* 验证段，占用16个字节 */
	unsigned char auth[16];			
	/* attribute起始指针 */
	//char *data;						
};

/* 读取pcap文件 */

/* 网络初始化，原始套接字 */

int net_setup();

/* 获取radius数据 */

struct radiushdr get_radius(char *buff);

/* 获取用户名 */

char *parse_radius(struct radiushdr);

/* 是否是黑名单 */

int is_black_table(char *username);



int main (int argc, const char * argv[])  
{
	struct ethhdr *eth;
	struct iphdr *ip;
   	struct udphdr *udp;
	struct radiushdr *radius_head;
	int i = 0,j = 0, count = 0, readSize = 0, ret = 0;
	char *buff = NULL;
	pcap_file_header  pfh;  
	pcap_header  ph;  

	FILE *fp = fopen(PCAP_FILE, "rw");  

	if (fp==NULL) {  
		
	    	fprintf(stderr, "Open file %s error.",PCAP_FILE);  
		ret = ERROR_FILE_OPEN_FAILED;  
	    	goto ERROR;  
	}  

	fread(&pfh, sizeof(pcap_file_header), 1, fp);     

	//prinfPcapFileHeader(&pfh);  

	buff = (char *)malloc(MAX_ETH_FRAME);  
	for (count=1; ; count++) 
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
			ret = ERROR_MEM_ALLOC_FAILED;  
			goto ERROR;  
		}  

		//获取数据包内容
		readSize=fread(buff,1,ph.capture_len, fp);  
		if (readSize != ph.capture_len) {  
			free(buff);  
			fprintf(stderr, "pcap file parse error.\n");  
			ret = ERROR_PCAP_PARSE_FAILED;  
			goto ERROR;  
		}  
		//以太帧
		eth = (struct ethhdr*)buff;
		//ip
		ip = (struct iphdr*)(buff + sizeof(struct ethhdr));
		//udp
		udp = (struct udphdr*)(buff + sizeof(struct ethhdr) + sizeof(struct iphdr));
		
		/* 调整当前指针，指向应用层数据 */

		int begin = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
		
		/* 初始化radius指针 */

		radius_head = (struct radiushdr*)&buff[begin];
		
		/* code identifier len, authorize等属于协议头部内容 */
		if(radius_head->code != 4)
			continue;
		printf("IP:%-16s", inet_ntoa(ip->saddr)); 
		printf("source: %-5u dest:%-5u ", ntohs(udp->source), ntohs(udp->dest));

		printf("code: %d ", radius_head->code);
		printf("identifier: %x auth:", radius_head->identifier);
		for(i = 0;i<sizeof(radius_head->auth)/sizeof(unsigned char); i++)
			printf("%x", radius_head->auth[i]);
		printf("\n");		

		/* 调整当前指针，指向radius协议属性部分 */
		begin = begin + sizeof(struct radiushdr);
		
		unsigned char type, len;
		char *value;

		//解析属性域
		for(i = begin; i<readSize; )
		{
			/* 第一字节为类型 */
			type = (unsigned char)buff[i];
			/* 第三字节为属性长度，根据属性长度确定整个属性的范围 */
			len = (unsigned char)buff[i+1];
			if(len == 0)
				break;
			if(type == 1)
			{
				//提取username
				char username[20];
				sprintf(username,"%d", buff[i+2]-48);
				for(j = 1; j<len-2;j++)
					sprintf(username, "%s%d",username, (unsigned char)buff[i+2+j]-48);
				username[strlen(username)] = 0;
				printf("username:%s\n", username);
				break;
			}
			//读取下一个属性
			i = i + len;
		}
		if (feof(fp) || readSize <=0 ) {   
			break;  
		}  
	}  
	ERROR:  
	if (buff) {  
	    free(buff);  
	    buff=NULL;  
	}   
	if (fp) {  
	    fclose(fp);  
	    fp=NULL;  
	}     

	return ret;  
}  
