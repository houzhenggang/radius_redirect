
/*
 * 附加功能:初始化配置黑名单(配置ID)
 *		将文件中的黑名单发送到radius解析程序
 * 
 * * */

#include <sys/types.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "idcfg.h"

//黑名单ID存储路径

#define CONFIG_ID "../../config/id.conf"

/* 消息队列ID */
int  msgqid;


int get_msg_connect()
{
	int msgqid = 0;
	msgqid = msgget(MSGKEY,0777);
	if(msgqid == -1)
		error("msgget");
	return msgqid;
}



void show_all_ids()
{

}

int main(int argc,char *argv[])
{
	int type;
	char id[30];
	FILE *fp = NULL;
	msgqid = get_msg_connect(MSGKEY, 0777);
	
	printf("初始化当前黑名单信息.....\n");
	printf("+----------------+--------------+\n");
	fp = fopen(CONFIG_ID, "r");
	if(fp == NULL)
		error("fopen");

	while(fscanf(fp, "%s", id) != EOF)
	{
		fprintf(stderr, "读取 %s\n", id);
		msg.o_type = T_ADD_ID;
		strcpy(msg.id, id);
		msgsnd(msgqid, &msg, 1024, 0);
		fprintf(stderr,"发送ID %s 到Radius成功...\n", id);
	}

	printf("+---------------+---------------+\n");
	
	printf("黑名单初始化成功，如果需要对黑名单进行添加和删除操作，请运行idcfg，如果要绕过Radius解析程序，直接向内核添加或删除操作，请运行idipcfg程序\n");
	return 0;
}
