/*
  * This is a json-c test program
  */
#include "json_parser.h"

#define WEB_REDIRECT_MISC_FULLNAME              "/dev/" ZCOM_MISC_NAME
typedef enum WebRedirectMiscCmd_t
{
	WEB_REDIRECT_IOCTL_PLATFORM_GET     = 0x01,
	WEB_REDIRECT_IOCTL_PLATFORM_SET,
} WebRedirectMiscCmd_t;


#define BUF_LEN 1024

/* -----------------------------------------------------------------------------
 *  *  * Wbe Redirect Misc Ioctl
 *   *   *---------------------------------------------------------------------------*/
int WebRedirectMiscIoctl(WebRedirectMiscCmd_t MiscID, void* pData)
{
	int	fd = open(ZCOM_MISC_FULLNAME, O_RDWR);
	int	iResult = -1;
	if (-1!=fd)
	{
		iResult = ioctl(fd, MiscID, pData);
		close(fd);
	}
	return iResult;
}

//void json_parse_object(json_object *obj, int i);

void json_parse_object(char  *buf);

JsonTask_t g_JsonTask = { 0 };
static JsonTaskData_t *g_pJsonTaskData = NULL;
static JsonPlans_t *g_pJsonPlan = NULL;
static JsonTargetList_t *g_pJsonTarget = NULL;
ping_t pingt;
ping_response_t ping_res;
char *replace(char *src)
{
    int len = strlen(src);
    int i;
    for(i = 0; i<len-2; i++)
        src[i]=src[i+1];
    src[len-1]='\0';
    src[len-2]='\0';
    return src;
}
/*
void ping_response_parse(char *buf)
{
	json_object *new_obj = json_tokener_parse(buf);
	json_object *work_obj = json_object_object_get(new_obj, "work");
	ping_res.work = atoi(json_object_to_json_string(work_obj)); 	
	json_object *blacklist_obj = json_object_object_get(blacklist_obj, "blacklist");
	ping_res.work = atoi(json_object_to_json_string(tasklist_obj)); 	
	ping_res.work = atoi(json_object_to_json_string(work_obj)); 	
	printf("ulUpate %u\n",pjsontask->ulUpdate);
	


}

*/



void ping_object()
{
	json_object  *load_object, *cpu_object , *mem_object ,*net_input_object ,*net_output_object ;
	load_object = json_object_new_object();
	json_object_object_add(load_object, "load", json_object_new_double(pingt.load));

	cpu_object = json_object_new_object();
	json_object_object_add(cpu_object, "cpu", json_object_new_double(pingt.cpu));

	mem_object = json_object_new_object();
	json_object_object_add(mem_object, "mem", json_object_new_double(pingt.mem));

	net_input_object = json_object_new_object();
	json_object_object_add(net_input_object, "net_input", json_object_new_double(pingt.net_input));

	net_output_object = json_object_new_object();
	json_object_object_add(net_output_object, "net_output", json_object_new_double(pingt.net_output));

	load_object = json_object_new_object();
	json_object_object_add(load_object, "load", json_object_new_double(pingt.load));

}
void json_parse_object(char  *buf)
{
	json_object *new_obj = json_tokener_parse(buf);

	json_object *update_obj = json_object_object_get(new_obj, "update");
    //printf("\t%u  %d\n",  atoi(json_object_to_json_string(update_obj)),strlen(json_object_to_json_string(update_obj)));
	
	JsonTask_t *pjsontask = (struct JsonTask_t *)malloc(sizeof(JsonTask_t));
	
	pjsontask->ulUpdate = atoi(json_object_to_json_string(update_obj)); 	
	printf("ulUpate %u\n",pjsontask->ulUpdate);
	


	json_object *sub2obj = json_object_object_get(new_obj, "tasks");
        if(NULL==sub2obj)
        {
            printf("tasks is not exit !\n");
        }
        else
        {
			int i;
			pjsontask->jsonTaskDataNum = json_object_array_length(sub2obj);
        	for(i=0; i < json_object_array_length(sub2obj); i++){    
		    	
				//pjsontask->JsonTaskData[i]  = (struct JsonTaskData_t *)malloc(sizeof(JsonTaskData_t));
				json_object *obj = json_object_array_get_idx(sub2obj, i);
		//	json_object *src_url_type_obj = json_object_object_get(obj, "src_url_type");
          //      printf("\t%d  %d\n",  json_object_to_json_int(src_url_type_obj),strlen(json_object_to_json_int(src_url_type_obj)));

				json_object *src_url_type_obj = json_object_object_get(obj, "src_url_type");
                //printf("\t%s  %d\n",  json_object_to_json_string(src_url_type_obj),strlen(json_object_to_json_string(src_url_type_obj)));
				pjsontask->JsonTaskData[i].ulSrcUrlType = atoi(json_object_to_json_string(src_url_type_obj));
				printf("url_type  %u\n",pjsontask->JsonTaskData[i].ulSrcUrlType);
				
				json_object *src_url_obj = json_object_object_get(obj, "src_url");
                //printf("\t%s  %d\n",  json_object_to_json_string(src_url_obj),strlen(json_object_to_json_string(src_url_obj)));
				memcpy(pjsontask->JsonTaskData[i].szSrcUrl,replace(json_object_to_json_string(src_url_obj)),strlen(replace(json_object_to_json_string(src_url_obj)))); 	
				printf("szSrcurl  %s\n",pjsontask->JsonTaskData[i].szSrcUrl);
				
				json_object *task_type_obj = json_object_object_get(obj, "task_type");
				pjsontask->JsonTaskData[i].ulTaskType = atoi(json_object_to_json_string(task_type_obj));
                printf("\t%s  %d\n",  json_object_to_json_string(task_type_obj),strlen(json_object_to_json_string(task_type_obj)));
				printf("task_type  %u\n",pjsontask->JsonTaskData[i].ulTaskType);

	
	/*
	json_object *plans_obj = json_object_object_get(obj, "plans");

                json_object *obj1 = json_object_array_get_idx(plans_obj, 0);
	*/
				json_object *target_list_obj = json_object_object_get(obj, "target_list");
                printf("\t%s  %d\n",  json_object_to_json_string(target_list_obj),strlen(json_object_to_json_string(target_list_obj)));
				int j;
				pjsontask->JsonTaskData[i].jsonTargetListNum = json_object_array_length(target_list_obj);
				printf("listNum %d\n",pjsontask->JsonTaskData[i].jsonTargetListNum);				
    			for(j=0; j < json_object_array_length(target_list_obj); j++){    
		    
					json_object *obj2 = json_object_array_get_idx(target_list_obj, j);
	
					json_object *url_obj = json_object_object_get(obj2, "url");
					memcpy(pjsontask->JsonTaskData[i].JsonTargetList[j].url,replace(json_object_to_json_string(url_obj)),strlen(replace(json_object_to_json_string(url_obj)))); 	
					printf("url  %s\n",pjsontask->JsonTaskData[i].JsonTargetList[j].url);
				
					//printf("\t%s  %d\n", json_object_to_json_string(url_obj),strlen(json_object_to_json_string(url_obj)));
					json_object *cookie_obj = json_object_object_get(obj2, "cookie");
					memcpy(pjsontask->JsonTaskData[i].JsonTargetList[j].cookie,replace(json_object_to_json_string(cookie_obj)),strlen(replace(json_object_to_json_string(cookie_obj)))); 	
					printf("cookie  %s\n",pjsontask->JsonTaskData[i].JsonTargetList[j].cookie);
					//printf("\t%s  %d\n", json_object_to_json_string(cookie_obj),strlen(json_object_to_json_string(cookie_obj)));
					
					json_object *weight_obj = json_object_object_get(obj2, "weight");
					pjsontask->JsonTaskData[i].JsonTargetList[j].ulWeight = atoi(json_object_to_json_string(weight_obj));
					printf("weight  %u\n",pjsontask->JsonTaskData[i].JsonTargetList[j].ulWeight);
					//printf("\t%s  %d\n", json_object_to_json_string(weight_obj),strlen(json_object_to_json_string(weight_obj)));
				
					json_object *start_obj = json_object_object_get(obj2, "start");
					pjsontask->JsonTaskData[i].JsonTargetList[j].ulStart = atoi(json_object_to_json_string(start_obj));
					printf("start  %u\n",pjsontask->JsonTaskData[i].JsonTargetList[j].ulStart);
					printf("\t%s  %d\n", json_object_to_json_string(start_obj),strlen(json_object_to_json_string(start_obj)));
					
					json_object *end_obj = json_object_object_get(obj2, "end");
					pjsontask->JsonTaskData[i].JsonTargetList[j].ulEnd = atoi(json_object_to_json_string(end_obj));
					printf("end  %u\n",pjsontask->JsonTaskData[i].JsonTargetList[j].ulEnd);
				//	printf("\t%s  %d\n", json_object_to_json_string(end_obj),strlen(json_object_to_json_string(end_obj)));
	
					json_object *tid_obj = json_object_object_get(obj2, "tid");
					pjsontask->JsonTaskData[i].JsonTargetList[j].ulTid = atoi(json_object_to_json_string(tid_obj));
					printf("tid  %u\n",pjsontask->JsonTaskData[i].JsonTargetList[j].ulTid);
					//printf("\t%s  %d\n", json_object_to_json_string(tid_obj),strlen(json_object_to_json_string(tid_obj)));
	

            json_object_put(url_obj);
            json_object_put(cookie_obj);
            json_object_put(weight_obj);
            json_object_put(start_obj);
            json_object_put(end_obj);
            json_object_put(tid_obj);
            json_object_put(obj2);
	}
           //printf("sub2obj:%s\n", json_object_to_json_string(sub2obj));
            json_object_put(obj);
            json_object_put(src_url_obj);
            json_object_put(task_type_obj);
            json_object_put(src_url_type_obj);
    //        json_object_put(plans_obj);
            //json_object_put(obj1);
        json_object_put(target_list_obj);
    }
            json_object_put(sub2obj);
            json_object_put(update_obj);
            json_object_put(new_obj);
        }
}

size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
	if (strlen((char *)stream) + strlen((char *)ptr) > 999999) 
		return 0;
	strcat(stream, (char *)ptr);
	return size*nmemb;
}



int curl_handler(char* str,char* arg)
{
//	signal(SIGALRM, curl_handler);
 //   alarm(1);
	 CURL *curl;             //定义curl类型的指针
    CURLcode res;           //定义curlcode类型的变量，保存返回状态码
 
    curl = curl_easy_init();        //初始化一个CURL类型的指针
    if(curl!=NULL)
    {
        //设置curl选项. 其中CURLOPT_URL是让用户指定url. argv[1]中存放的命令行传进来的网址
       	printf("arg:%s\n", arg);
        curl_easy_setopt(curl, CURLOPT_URL, arg);
        //调用curl_easy_perform 执行我们的设置.并进行相关的操作. 在这里只在屏幕上显示出来.
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);//设置写数据的函数
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, str);//设置写数据的变量
		res = curl_easy_perform(curl);
	
		//清除curl操作.
        curl_easy_cleanup(curl);
       printf("str:%c%c%c%c\n", str[0],str[1],str[2],str[3]);
     }
	return 0;   
}


void *ping_thread()
{
	pthread_exit(NULL);
}


void *blacklist_thread()
{
	pthread_exit(NULL);
}


void *tasklist_thread()
{
    
    char str1[10000];
	while(1){
		curl_handler(str1,tasklist_url);
		json_object *obj=json_tokener_parse(str1);
        if (obj == NULL) {
            printf("This is not a json string!\n");
            return -1;
        }
        
        json_parse_object(str1);
		
		sleep(2);
    }
    
	pthread_exit(NULL);
}


void *log_thread()
{
	pthread_exit(NULL);
}




#define THREAD_NUM 4
pthread_t thread[THREAD_NUM];


void thread_create()
{
	int temp;
	memset(&thread, 0, sizeof(thread));
	
    
	if((temp = pthread_create(&thread[0], NULL, ping_thread, NULL)) != 0)
		printf("Failed to ping thread \n");
	else
		printf("Successed to create ping_thread \n");
    
    
	if((temp = pthread_create(&thread[1], NULL, blacklist_thread, NULL)) != 0)
		printf("Failed to create blacklist_thread \n");
	else
		printf("Successed to create blacklist_thread \n");
    
	if((temp = pthread_create(&thread[2], NULL, tasklist_thread, NULL)) != 0)
		printf("Failed to tasklist thread \n");
	else
		printf("Successed to tasklist_thread \n");
    
    
	if((temp = pthread_create(&thread[3], NULL, log_thread, NULL)) != 0)
		printf("Failed to create log_thread \n");
	else
		printf("Successed to create log_thread \n");
    
}


void thread_wait()
{
	int temp = THREAD_NUM;
	while(temp--){
		if(thread[temp] !=0){
			pthread_join(thread[temp],NULL);
			printf("thread[%d] fineshed!\n",temp);
        }
	}
}



int main (int argc, char *argv[]) 
{
    if(argc != 2)
    {
        printf("usage : file <url>;/n");
        exit(1);
    }
	tasklist_url = argv[1];
	thread_create();
	thread_wait();
    }

	return 0;	
}	

