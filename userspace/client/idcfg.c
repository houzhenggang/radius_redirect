
/*
 * 附加功能:简单配置黑名单(配置ID)
 * 
 * * */

#include <sys/types.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "idcfg.h"
#define CONFIG_ID "../../config/id.conf"
/* 消息队列ID */
int  msgqid;

#define error(msg) \
	{fprintf(stderr,"%s error with:%s\n", msg, strerror(errno));exit(-1);}

int get_msg_connect()
{
	int msgqid = 0;
	msgqid = msgget(MSGKEY,0777);
	if(msgqid == -1)
	{
		fprintf(stderr,"消息队列服务端未启动，请检查Radius解析程序是否已经启动\n");
		error("msgget");
	}
	return msgqid;
}

void show_all_ids()
{
	char id[30];
	FILE *fp = fopen(CONFIG_ID, "r");
	if(fp == NULL)
		error("fopen");
	printf("当前黑名单列表\n");
	printf("+-----------------+------------------+\n");
	while(fscanf(fp, "%s", id) != EOF)
		printf("%s\n", id);

	printf("+-----------------+------------------+\n");
	if(fp != NULL)
		fclose(fp);
}


int main(int argc,char *argv[])
{
	int type;
	char id[30];
	msgqid = get_msg_connect(MSGKEY, 0777);
	
	fprintf(stdout,"\n黑名单管理程序提供对黑名单的添加和删除操作\n");
	show_all_ids();

	while(1)
	{
		printf("输入操作类型:");
		//scanf万万不能用
		scanf("%d", &type);
		if(type == 0)
			break;

		if(type != T_ADD_ID && type != T_REMOVE_ID)
		{
			fprintf(stderr,"检查输入,输入0表示退出,1表示添加黑名单那ID，2表示删除黑名单ID\n");
			continue;
		}
		printf("请输入操作的用户ID:");
		
		//把scanf后面的\n从缓冲中读取出来
		getchar();	
		fgets(id, MAX_ID_LEN, stdin);
		if(strlen(id)>30)
		{
			fprintf(stderr,"黑名单ID长度限制在30个字符以内\n");
			continue;
		}
		//fgets最后有个换行
		id[strlen(id)-1] = 0;

		msg.o_type = type;
		strcpy(msg.id, id);
		if( msgsnd(msgqid, &msg, 1024, 0) <0)
			error("msgsnd");
		


		fprintf(stdout, "操作成功\n");
		sleep(1);
		show_all_ids();

	}

	printf("程序即将结束.....bye\n");
	return 0;
}
