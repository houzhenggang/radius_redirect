#ifndef _JSONTEST_H_
#define _JSONTEST_H_

#include "common.h"
#define MAX_URL_SIZE	256
#define MAX_COOKIE_SIZE	4 * 1024
#define MAX_TASK_DATA   10
#define MAX_PLANS_LIST   10
#define MAX_TASK_LIST   10

const char *szJsonDemo = "{\"update\": 1396252388, ""\"task\":[{\"src_url_type\": 1, \"src_url\": \"www.baidu.com/search\", ""\"task_type\": 302, \"target_list\": [{\"url\": \"www.mydomain.com/123\", " "\"cookie\": \"\", \"weight\": 32, \"start\": 1396252388, \"end\": 1396252488, " "\"tid\": 1000023}]}]}";

typedef struct JsonTargetList_t
{
	uint32_t target_type;
	char url[MAX_URL_SIZE];
	char cookie[MAX_COOKIE_SIZE];
	uint32_t ulWeight;
	uint32_t ulTid;
} JsonTargetList_t;

typedef struct JsonPlans_t
{
	uint32_t pid;
	uint32_t ulWeight;
	uint32_t pro;
	uint32_t end;
	JsonTargetList_t  targetList[MAX_TASK_LIST];
} JsonPlans_t;

typedef struct JsonTaskData_t
{
	uint32_t ulSrcUrlType;
	char szSrcUrl[MAX_URL_SIZE];
	JsonPlans_t jsonPlansList[MAX_PLANS_LIST];
} JsonTaskData_t;

typedef struct JsonTask_t
{
	uint32_t ulUpdate;
	JsonTaskData_t JsonTaskData[MAX_TASK_DATA];
} JsonTask_t;
#endif // _JSONTEST_H_
