
/*
 * 主模块:radius协议解析
 *
 * */

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

#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <sys/types.h>
#include <asm/types.h>

#include "_slist/slist.h"

/* 消息队列值 */
#define MSGKEY 75
/* 以太帧头最大值 */
#define MAX_ETH_FRAME 1514  

#define T_ADD_ID	1
#define T_REMOVE_ID	2

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
}*radius_head;

/* 黑名单ID表 */
struct id_table
{

	char id[20];
	//其他信息
}id;

/* 发送给内核的包含黑名单id对应的ip */
struct 
{
	/* 操作类型 */
	int o_type;
	/* 操作ID */
	char id[30];
}msg;
/* 读取到的数据大小 */
int readSize;
/* 读取到的数据的缓冲区 */
char *buff = NULL;
/* 读取到的用户名 */
unsigned char username[20];
/* 黑名单ID表*/
struct slist *id_list;
/* 要发给内核重定向程序的黑名单ID对应的IP*/
char send_ip[30];
/* 错误信息 */
#define error(msg) \
	{fprintf(stderr, "%s error:%s\n", msg, strerror(errno));exit(-1);}
/* 黑名单文件 */
#define BLACK_TABLE "../../config/id.conf"

/* 获取radius数据 */
void get_radius();

/* 获取radius协议中的用户名和ip地址*/
void parse_radius();

/* 是否是黑名单 */
int is_black_table();

/* 获取radiu协议头 */
void get_radius();

//<<===========================================================<<
//以下为与radius有关的函数
void get_radius()
{
	struct ethhdr *eth;
	struct iphdr *ip;
   	struct udphdr *udp;
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
}

/*
 * 根据radius协议内容解析处radius相关字段
 * radius参考rfc
 *
 * */
void parse_radius()
{
	/* 调整当前指针，指向radius协议属性部分 */

	int begin = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct radiushdr);
	int i,j;
	unsigned char att_type, len;
	char *value;

	memset(username, 0, sizeof(username));
	memset(send_ip, 0, sizeof(send_ip));

	//解析属性域
	for(i = begin; i<readSize; )
	{
		/* 第一字节为类型 */
		att_type = (unsigned char)buff[i];
		/* 第三字节为属性长度，根据属性长度确定整个属性的范围 */
		len = (unsigned char)buff[i+1];
		if(len == 0)
			break;
		//根据RFC，类型是1的是用户名
		if(att_type == 1)
		{
			//提取username
			sprintf(username,"%u", (unsigned char)buff[i+2]-48);
			for(j = 1; j<len-2;j++)
				sprintf(username, "%s%u",username, (unsigned char)buff[i+2+j]-48);
			username[strlen(username)] = 0;
		}
		//根据RFC，类型是8的是framp ip
		else if(att_type == 8)
		{
			sprintf(send_ip, "%u.", (unsigned char)buff[i+2]);
			for(j = 1; j<len-2;j++)
				sprintf(send_ip, "%s%d.", send_ip,(unsigned char)buff[i+2+j]);
			send_ip[strlen(send_ip)-1] = 0;
		}
		//读取下一个属性
		i = i + len;
	}
}

/*
 * 函数名:is_black_table
 * 参数:void
 * 说明:判断是否是黑名单
 * 原理：黑名单存储在id_list链表中，从链表中查找用户名是否存在
 *
 * */
int is_black_table(void)
{
	int i = 0; 
	struct slist *pos;
	slist_travel(pos,id_list)	
	{
		struct id_table *temp = (struct id_table*)(pos->data);
		if(strcmp(username, temp->id) == 0)
			return 1;
	}
	return 0;
}

//<<===========================================================<<
//以下为与内核重定向交互的函数

/* netlink 协议号为26的负责内核与radius之间的交互 */
#define NETLINK_RADIUS_KERNEL 26		
/* 最大负载 */
#define MAX_PAYLOAD 512	

/*
 * 函数名:send_redirect
 * 参数:要发送的IP地址
 * 说明:采用netlink的方式与内核进行通信
 *
 * */

int send_redirect(char type,char *id,char *ip)
{

	//通信地址结构
	struct sockaddr_nl nl_src_addr, nl_dest_addr;
	char str[100];
	//消息报头
	struct nlmsghdr *nlh = NULL;
	//IO
	struct iovec iov;
	int nl_fd;
	//消息体
	struct msghdr nl_msg;
	nl_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_RADIUS_KERNEL);
	if(nl_fd<0)
	{
		perror("socket");
		return 0;
	}
	memset(&nl_msg, 0, sizeof(nl_msg));

	memset(&nl_src_addr, 0, sizeof(nl_src_addr));
	nl_src_addr.nl_family = AF_NETLINK;
	nl_src_addr.nl_pid = getpid();
	nl_src_addr.nl_groups = 0;
#if 0
	if(bind(nl_fd,(struct sockaddr*)&nl_src_addr, sizeof(nl_src_addr))<0)
	{
		perror("bind");
		return 0;
	}
#endif

	memset(&nl_dest_addr, 0, sizeof(nl_dest_addr));
	nl_dest_addr.nl_family = AF_NETLINK;
	nl_dest_addr.nl_pid = 0;
	
	nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;
	
	sprintf(str, "%c:%s:%s", type, id, ip);
	strcpy((char*)NLMSG_DATA(nlh), str);
	
	iov.iov_base = (void*)nlh;
	iov.iov_len = nlh->nlmsg_len;
	nl_msg.msg_name = (void*)&nl_dest_addr;
	nl_msg.msg_namelen = sizeof(nl_dest_addr);
	nl_msg.msg_iov = &iov;
	nl_msg.msg_iovlen = 1;

	printf("开始发送信息%s.\n", str);

	if(sendmsg(nl_fd, &nl_msg, 0)<0)
	{
		perror("sendmsg");
		return 0;
	}
	close(nl_fd);

	return 1;

}

//<<===========================================================<<
//以下为负责与黑名单id配置相关的操作

/*
 * 函数名:msg_server
 * 参数:void
 * 说明:消息队列的服务器端，也是线程的回调函数
 *
 * */

void msg_server( )
{
	int msgqid, i = 0,j = 0;
	struct slist *pos;
	FILE *f;

	msgqid=msgget(MSGKEY,0777|IPC_CREAT);  /*创建消息队列*/
	do 
        {
		msgrcv(msgqid,&msg,1030,0,0);   /*接收消息*/
		strcpy(id.id, msg.id);
		id.id[strlen(id.id)] = 0;
		if(msg.o_type == T_ADD_ID)
		{
			printf("收到控制端的添加黑名单命令\n");
			printf("将用户:%s加入黑名单\n", id.id);
			slist_travel(pos, id_list)
			{
				struct id_table *id_temp = (struct id_table*)pos->data;
				if(strcmp(id_temp->id, id.id) == 0)
				{
					fprintf(stderr,"ID %s 已存在黑名单中\n", id.id);
					goto end;
				}
			}
			slist_add_head(id_list, &id, sizeof(id));
		}
		else if(msg.o_type == T_REMOVE_ID)
		{
			printf("收到控制端的删除黑名单命令\n");
			printf("将用户%s从黑名单删除\n", id.id);
			//删除链表数据, 只匹配id
			slist_travel(pos ,id_list)
			{
				struct id_table *id_temp = (struct id_table*)pos->data;
				if(strcmp(id_temp->id, id.id) == 0)
					slist_remove(id_list, id_temp, sizeof(*id_temp));
			}
			printf("告诉内核删除与%s相关的id到ip的映射关系\n", id.id);
			//告诉内核删哪个id
			send_redirect('d', id.id,"NULL");
		}

end:
		f = fopen(BLACK_TABLE,"rw+");
		if(f == NULL)
			error("fopen");
		printf("现有黑名单ID:\n");
		printf("+-----------------+------------------------+\n");
		struct slist *pos;
		struct id_table *temp;
		slist_travel(pos, id_list)
		{
			temp = (struct id_table*)(pos->data);
			printf("ID:%s\n",temp->id );
			fprintf(f,"%s\n", temp->id);
			fflush(f);
		}
		printf("+----------------+-------------------------+\n");
		fclose(f);

	}while(1);

	fclose(f);

	msgctl(msgqid,IPC_RMID,0);  /*删除消息队列，归还资源*/
	exit(0);
}
//<<====================================================================<<
//以下为主程序，负责捕获数据，判断是否为radius协议，如果是，则解析radius
//解析处id和ip，如果id是黑名单上的id，则将ip发给内核重定向

int main (int argc, const char * argv[])  
{

	if(argc != 2)
	{
		fprintf(stderr,"usage<device>\n");
		fprintf(stderr,"请输入网卡，比如 eth0，网卡信息请用ifconfig来查看\n");
		exit(-1);
	}

	int i = 0,j = 0, count = 0, ret = 0;
	//黑名单文件
	FILE *black = NULL;
	
	//初始化黑名单id表
	slist_init(id_list);
	//消息队列线程，负责接收配置数据
	pthread_t recv_thread;
	if(pthread_create(&recv_thread, NULL, msg_server, NULL) <0)
	{
		perror("pthread_create");
		exit(-1);
	}
	//打开黑名单文件
	black = fopen(BLACK_TABLE, "rw");
	if(black == NULL)
		error("open blacktable");
	//读取黑名单文件
	while(fscanf(black, "%s",id.id) != EOF)
	{
		slist_add_head(id_list, &id, sizeof(id));
	}

	fclose(black);
	printf("根据记录，当前黑名单列表如下\n");
	printf("+-----------------------------------+\n");
	
	struct slist *pos;
	slist_travel(pos,id_list)
	{
		struct id_table *temp = (struct id_table*)(pos->data);
		printf("%s\n", temp->id);
	}
	printf("+----------------------------------+\n");

	int sockfd;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct tcphdr *tcp;
	if(0>(sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))))
	{
		perror("socket");
		exit(-1);
	}

	struct ifreq ethreq;
	strncpy(ethreq.ifr_name, argv[1], IFNAMSIZ);
	ioctl(sockfd, SIOCGIFFLAGS, &ethreq);
	ethreq.ifr_flags |=IFF_PROMISC;
	if(-1== ioctl(sockfd, SIOCGIFFLAGS, &ethreq))
	{
		perror("ioctl2");
        	close(sockfd);
		exit(-1);
	}

	buff = (char *)malloc(MAX_ETH_FRAME);  
	if(buff == NULL)
		error("malloc");

	while(1)
	{
		readSize = recvfrom(sockfd, buff, 2048, 0, NULL, NULL);
		eth = (struct ethhdr*)buff;
		
		int type = ntohs(eth->h_proto);
		
		//ip协议
		if(type == ETH_P_IP)
		{
			ip = (struct iphdr*)(buff + sizeof(struct ethhdr));
			//tcp协议
			if(ip->protocol == 6)
			{
				tcp = (struct tcphdr*)(buff + sizeof(struct iphdr) + sizeof(struct ethhdr));
				//radius协议,从1812端口发过来，1813号端口接收
				if( (ntohs(tcp->dest)) == 1813 && ntohs(tcp->source)==1812 )
				{
					get_radius();
					if(radius_head->code != 4)
						continue;
					parse_radius();
					fprintf(stdout, "username:%s ", username);
					if(is_black_table())
					{
						fprintf(stdout, "黑名单,发送IP：%s 给重定向程序\n",send_ip);
						fprintf(stdout,"发送IP部分采用netlink方法\n");
						if(send_redirect('a', username, send_ip))
						{
							fprintf(stdout,"发送给内核重定向程序\n");
						}
						else
							fprintf(stderr,"发送失败\n");
					}
					else
						fprintf(stdout, "不是黑名单\n");
				}
				printf("是tcp协议，来个端口测试抓包是否正确:source:%d\n", ntohs(tcp->source));
			}
			struct in_addr add;
			add.s_addr = ip->saddr;
			printf("不是tcp协议，来个ip测试抓包是否正确:IP:%s\n", inet_ntoa(add));
		}
		
	}
	return 0;  
}  
