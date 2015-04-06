/*************************************************************************
    > File Name: nlkernel.c
    > Author: ICKelin
    > Mail: 18277973721@sina.cn 
    > Created Time: 2015年04月03日 星期五 15时24分28秒
 ************************************************************************/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/netlink.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <linux/list.h>

#define NETLINK_URL_KERNEL 25

struct sock *g_nl_sk = NULL;

struct ipConfig
{
	char ip[30];
	char id[30];
}ipc;

void nl_ready(struct sk_buff *__skb)
{
	//skb结构
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	skb = skb_get(__skb);

	nlh = nlmsg_hdr(skb);
	memset(&ipc, 0,sizeof(struct ipConfig));
	memcpy(&ipc, (struct ipConfig*)NLMSG_DATA(nlh),sizeof(ipc));
	printk("recv ip::%s\n", ipc.ip);
	printk("recv id::%s\n", ipc.id);
	
	
	kfree_skb(skb);
}

int init_module()
{
	//netlink套接字地址结构
	struct netlink_kernel_cfg cfg = {
		.input = nl_ready,
	};
	g_nl_sk = netlink_kernel_create(&init_net,NETLINK_URL_KERNEL,&cfg);
	
	return 0;
}

void cleanup_module()
{
	if(g_nl_sk != NULL)
		sock_release(g_nl_sk->sk_socket);
}
