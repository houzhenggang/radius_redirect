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

void nl_ready(struct sk_buff *__skb)
{
	//skb结构
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	char str[512];
	skb = skb_get(__skb);

	nlh = nlmsg_hdr(skb);
	memset(str, 0,sizeof(str));
	strcpy(str,(char*)NLMSG_DATA(nlh));
	printk("recv str::%s\n", str);
	
	
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
