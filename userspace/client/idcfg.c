
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

//消息队列的KEY值
#define MSGKEY 75
#define MAX_ID_LEN	30

/* 用户操作类型，包括添加黑名单ID和
 * 删除黑名单ID两个类型 */

//添加黑名单ID
#define T_ADD_ID 1
/* 删除黑名单ID */
#define T_REMOVE_ID	2

/*
 * 消息体
 *
 * */
struct  msgform
{ 
	/* 操作类型 */
	int  o_type;
	/* 操作ID */
    char  id[30];
}msg;

/* 消息队列ID */
int  msgqid;

int main(int argc,char *argv[])
{
	int type;
	char id[30];
	msgqid = msgget(MSGKEY,0777);
	if(msgqid == -1)
	{
		fprintf(stderr, "消息队列服务器端未开启,请检查radius解析程序是否运行\n");
		exit(-1);
	}
	fprintf(stdout,"\n黑名单管理程序提供对黑名单的添加和删除操作\n");
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
		getchar();	
		fgets(id, MAX_ID_LEN, stdin);
		if(strlen(id)>30)
		{
			fprintf(stderr,"黑名单ID长度限制在30个字符以内\n");
			continue;
		}
		id[strlen(id)-1] = 0;

		msg.o_type = type;
		strcpy(msg.id, id);
		msgsnd(msgqid, &msg, 1024, 0);
		fprintf(stdout, "添加黑名单成功\n");
	}

	printf("程序即将结束.....bye\n");
	return 0;
}
