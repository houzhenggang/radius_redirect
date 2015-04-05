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

#define NETLINK_RADIUS 28

struct sock *g_nl_sk = NULL;

struct mylist
{
	char ip[30];
	struct list_head ip_list;
}msg;

void nl_ready(struct sk_buff *__skb)
{
	//skb结构
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct mylist *ip;
	struct list_head *pos;
	struct mylist *p;
	skb = skb_get(__skb);

	nlh = nlmsg_hdr(skb);
	ip = kmalloc(sizeof(struct mylist),GFP_KERNEL);
	if(!ip)
	{
		printk("kmalloc mem error\n");
		return -1;
	}
	memset(ip, 0,sizeof(struct mylist));
	INIT_LIST_HEAD(&ip->ip_list);
	strcpy(ip->ip,(char*) NLMSG_DATA(nlh));
	printk("recv ip::%s\n", ip->ip);
	list_add_tail(&(ip->ip_list), &(msg.ip_list));
#if 1
	list_for_each(pos, &msg.ip_list)
	{
		p = list_entry(pos, struct mylist,ip_list);
		if(p != NULL)
			printk("ip:%s\n", p->ip);
	}
#endif
	kfree_skb(skb);
}

int init_module()
{
	//netlink套接字地址结构
	struct netlink_kernel_cfg cfg = {
		.input = nl_ready,
	};
	INIT_LIST_HEAD(&msg.ip_list);
	g_nl_sk = netlink_kernel_create(&init_net,NETLINK_RADIUS,&cfg);
	
	return 0;
}

void cleanup_module()
{
	struct mylist *l,*next;
	if(g_nl_sk != NULL)
		sock_release(g_nl_sk->sk_socket);
	list_for_each_entry_safe(l,next,&(msg.ip_list),ip_list)
	{
		list_del(&l->ip_list);
		printk("Destroy IP:%s\n", l->ip);
		kfree(l);
	}

}
