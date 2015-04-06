/*
  * web  header
  */

#ifndef _WEB_REDIRECT_H_
#define _WEB_REDIRECT_H_

#include "common.h"

#define IP_VERSION_4	4
#define IP_VERSION_6	6

#define IP_HEAD_LEN		sizeof(struct iphdr)

#define DEFAULT_REDIRECT_URL "www.baidu.com"

const char *http_redirect_header = 
 
    "HTTP/1.1 301 Moved Permanently\r\n"
 
    "Location: http://%s\r\n"
 
    "Content-Type: text/html; charset=iso-8859-1\r\n"
 
    "Content-length: 0\r\n"
 
    "Cache-control: no-cache\r\n"
 
    "\r\n";

const char *popup_header = 
	"<SCRIPT LANGUAGE=\"javascript\">\r\n"
	"<!--\r\n"
	"window.open ('%s')\r\n"
	"-->\r\n"
	"</SCRIPT>\r\n";

typedef struct WebData_t
{
	uint8_t	*pBuf;
	uint32_t ulBufLen;
} WebData_t;

static inline void web_data_init(WebData_t *pData)
{
	pData->pBuf = NULL;
	pData->ulBufLen = 0;
}

static inline int web_data_empty(WebData_t *pData)
{
	return (pData->pBuf == NULL);
}

static inline void web_data_destroy(WebData_t *pData)
{
	if (pData == NULL)
		return;

	if ( likely( pData->pBuf != NULL ) ){  
        kfree( pData->pBuf );  
        pData->pBuf = NULL;  
    } 
    kfree( pData );
	pData = NULL;
}

static inline WebData_t *web_data_alloc(void)
{
	WebData_t *pTmp = NULL;
	pTmp = kzalloc(sizeof(WebData_t), GFP_KERNEL);
	if ( unlikely( NULL == pTmp ) ) {
		return NULL;
	}
	web_data_init(pTmp);
	return pTmp;
}

static inline char *web_popup_header(char *szPopupUrl)
{
	char *szPopupStr = NULL;
	uint32_t ulPopupLen = strlen(popup_header) + strlen(szPopupUrl);
	if ( ( szPopupStr = (char*)kzalloc(ulPopupLen, GFP_KERNEL) ) == NULL)
		return NULL;
	sprintf(szPopupStr, popup_header, szPopupUrl);
	return szPopupStr;
}

int web_build_url(const char *szUrl, WebData_t *pData);

///////////////////////////////////////////////////////////////////////////

typedef enum 
{
	ADD_IP,		//增加过滤IP
    DONOTHING,		//什么也不做
    ADD_URL_FILTER,			//添加过滤
    REMOVE_URL_FILTER			//删除URL过滤

} ACTION_TYPE;

//typedef struct WebPatriotData_t
typedef struct urlEntry_t
{
	uint8_t	*url;
	uint32_t urlLen;
} urlEntry_t;


//maybe we should check the url valid
typedef struct urlRedirectEntry_t
{
	urlEntry_t srcUrl;
	urlEntry_t dstUrl;
    ACTION_TYPE action;
    struct list_head list; 
} urlRedirectEntry_t;

struct ConfigSet 
{
    int32_t check_interval;
    int32_t url_number;
    struct list_head redirect_url_list_head;
	rwlock_t redirect_url_list_rwlock;
	//TODO: we need a timer to check the new configure
};

int web_redirect_build_url( const char *szUrl, urlEntry_t *dstUrlEntry);

/* -------------------------------------
 *  * Zcom Misc Command
 *   *-----------------------------------*/
#define WEB_REDIRECT_MISC_DEV_MAJOR				220	// refer to dev.txt
#define WEB_REDIRECT_MISC_NAME					"webRedirectMisc"
#define	WEB_REDIRECT_MISC_FULLNAME				"/dev/" ZCOM_MISC_NAME

typedef enum WebRedirectMiscCmd_t
{
	WEB_REDIRECT_IOCTL_PLATFORM_GET     = 0x01,
    WEB_REDIRECT_IOCTL_PLATFORM_SET,
} WebRedirectMiscCmd_t;
#endif // _WEB__H_
