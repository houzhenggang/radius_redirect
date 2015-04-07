
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

#define T_ADD_ID 1
#define T_REMOVE_ID	2

struct  msgform
{ 
	/* 操作类型 */
	int  o_type;
	/* 操作ID */
    char  id[30];
}msg;

void show_all_id();

