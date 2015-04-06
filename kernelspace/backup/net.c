/*
 *  net.c
 *  version 2
 *  Created on: 2013-04-17
 *      Author: humingming
 */

#include <string.h>
#include "net.h"
#include "time.h"


#define MAX_PACK 65535
extern pthread_mutex_t mut;

#define STRSIZE 1024
#define BUFSIZE 10240

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
typedef uint32_t u32;

FILE *logfile;
struct sockaddr_in source,dest;
unsigned char skb_buf[1024];
int i,j;
static unsigned long long total_payload=0;
static unsigned long long bps=0;
static unsigned long long pps=0;
static unsigned long long tcp=0;
static unsigned long long udp=0;
static unsigned long long icmp=0;
static unsigned long long others=0;
static unsigned long long igmp=0;
static unsigned long long total=0;
int skfd;

int num;

//json_object  * nic_name , *tcp_object , *udp_object ,*icmp_object ,*igmp_object ,*others_object ,*total_object ,*cpu_object ,*mem_object ,*pro_object ,*nic_object ,*my_total;

/*
* This is a version of ip_compute_csum() optimized for IP headers,
* which always checksum on 4 octet boundaries.
*
* By Jorge Cwik <jorge@laser.satlink.net>, adapted for linux by
* Arnt Gulbrandsen.
*/

static inline __wsum csum_tcpudp_nofold(uint32_t saddr, uint32_t daddr, unsigned short len, unsigned short proto, __wsum sum)
{
    __asm__(
            "addl %1, %0    ;\n"          //addl ¿¿
            "adcl %2, %0    ;\n"          //adcl ¿¿¿¿¿¿
            "adcl %3, %0    ;\n"
            "adcl $0, %0    ;\n"          //¿¿¿¿¿¿¿¿¿¿
            : "=r" (sum)
            : "g" (daddr), "g"(saddr), "g"((len + proto) << 8), "0"(sum)
           );

    return sum;
}
/*
static inline __wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr, unsigned short len, unsigned short proto, __wsum sum)
{
    __asm__(
            "addl %1, %0    ;\n"          //addl ¿¿
            "adcl %2, %0    ;\n"          //adcl ¿¿¿¿¿¿
            "adcl %3, %0    ;\n"
            "adcl $0, %0    ;\n"          //¿¿¿¿¿¿¿¿¿¿
            : "=r" (sum)
            : "g" (daddr), "g"(saddr), "g"((len + proto) << 8), "0"(sum)
           );

    return sum;
}
*/
/*

static inline unsigned long csum_tcpudp_nofold (unsigned long saddr, unsigned long daddr,unsigned short len, unsigned short proto,unsigned int sum)
{
	asm("addl %1, %0\n"
	    "adcl %2, %0\n"
	    "adcl %3, %0\n"	
	    "adcl $0, %0\n"
	   : "=r" (sum)
	   : "g" (daddr), "g" (saddr), "g" ((ntohs(len) << 16) + proto*256), "0" (sum));
	return sum;
}
*/
static inline uint16_t csum_fold(uint32_t sum)
{
						printf("%s,%d\n", __func__, __LINE__);
    __asm__(
        "addl %1, %0\n"
        "adcl $0xffff, %0"
        : "=r" (sum)
        : "r" (sum << 16), "0" (sum & 0xffff0000) 
    );

						printf("%s,%d\n", __func__, __LINE__);
    return (~sum) >> 16; 
}


static inline unsigned short int csum_tcpudp_magic(unsigned long saddr, unsigned long daddr,
                                                   unsigned short len, unsigned short proto,
                                                   unsigned int sum)
{
						printf("%s,%d\n", __func__, __LINE__);
    return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

static inline unsigned add32_with_carry(unsigned a, unsigned b)
{
    asm("addl %2, %0\n\t"
             "adcl $0, %0"
             : "=r" (a)
             : "0" (a), "r" (b));
    return a;
} 
static inline unsigned short from32to16(unsigned a)
{
    unsigned short b = a >> 16;
    asm ("addw %w2, %w0\n\t"
              "adcw $0, %w0\n"
              : "=r" (b)
              : "0" (b), "r" (a));
    return b;
}
static inline  unsigned  do_csum(const unsigned char *buff, unsigned len)
{
    unsigned odd, count;
    unsigned long result = 0;

    if (unlikely(len == 0))
        return result;

    /* ¿¿¿¿¿¿XXX0¿¿¿¿¿¿2¿¿¿¿ */
    odd = 1 & (unsigned long) buff;
    if (unlikely(odd)) {
        result = *buff << 8; /* ¿¿¿¿¿¿¿¿ */
        len--;
        buff++;
    }
    count = len >> 1; /* nr of 16-bit words¿¿¿¿¿¿¿1¿¿¿¿¿¿¿¿¿¿*/

    if (count) {
        /* ¿¿¿¿¿¿XX00¿¿¿¿¿¿4¿¿¿¿ */
        if (2 & (unsigned long) buff) {
            result += *(unsigned short *)buff;
            count--;
            len -= 2;
            buff += 2;
        }
        count >>= 1; /* nr of 32-bit words¿¿¿¿¿¿¿2¿¿¿¿¿¿¿¿¿¿ */

        if (count) {
            unsigned long zero;
            unsigned count64;
            /* ¿¿¿¿¿¿X000¿¿¿¿¿¿8¿¿¿¿ */
            if (4 & (unsigned long)buff) {
                result += *(unsigned int *)buff;
                count--;
                len -= 4;
                buff += 4;
            }
            count >>= 1; /* nr of 64-bit words¿¿¿¿¿¿¿4¿¿¿¿¿¿¿¿¿¿*/

            /* main loop using 64byte blocks */
            zero = 0;
            count64 = count >> 3; /* 64¿¿¿¿¿¿¿¿¿¿¿¿56¿¿¿¿¿¿¿¿¿¿ */
            while (count64) { /* ¿¿¿¿¿¿¿64¿¿¿ */
                asm ("addq 0*8(%[src]), %[res]\n\t"    /* b¿w¿l¿q¿¿¿¿8¿16¿32¿64¿¿¿ */
                          "addq 1*8(%[src]), %[res]\n\t"    /* [src]¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿0¿1¿ */
                          "adcq 2*8(%[src]), %[res]\n\t"
                          "adcq 3*8(%[src]), %[res]\n\t"
                          "adcq 4*8(%[src]), %[res]\n\t"
                          "adcq 5*8(%[src]), %[res]\n\t"
                          "adcq 6*8(%[src]), %[res]\n\t"
                          "adcq 7*8(%[src]), %[res]\n\t"
                          "adcq %[zero], %[res]"
                          : [res] "=r" (result)
                          : [src] "r" (buff), [zero] "r" (zero), "[res]" (result));
                buff += 64;
                count64--;
            }

            /* ¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿ */

            /* last upto 7 8byte blocks¿¿¿¿8¿8¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿7¿8¿¿ */
            count %= 8;
            while (count) {
                asm ("addq %1, %0\n\t"
                     "adcq %2, %0\n"
                     : "=r" (result)
                     : "m" (*(unsigned long *)buff), "r" (zero), "0" (result));
                --count;
                buff += 8;
            }

            /* ¿¿¿¿¿result¿¿32¿¿¿32¿ */
            result = add32_with_carry(result>>32, result&0xffffffff);

            /* ¿¿¿¿8¿¿¿¿¿¿¿¿4¿¿¿¿ */
            if (len & 4) {
                result += *(unsigned int *) buff;
                buff += 4;
            }
        }

       /* ¿¿¿¿4¿¿¿¿¿¿¿¿2¿¿¿¿ */
        if (len & 2) {
            result += *(unsigned short *) buff;
            buff += 2;
        }
    }

    /* ¿¿¿¿¿2¿¿¿¿¿¿¿¿1¿¿¿¿ */
    if (len & 1)
        result += *buff;

    /* ¿¿¿¿¿¿¿result¿¿32¿¿¿32¿ */
    result = add32_with_carry(result>>32, result & 0xffffffff); 

    /* ¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿¿ */
    if (unlikely(odd)) {
        result = from32to16(result); /* ¿¿¿result¿¿16¿ */
        /* result¿¿0 0 a b
         * ¿¿¿¿a¿b¿result¿¿¿0 0 b a
         */
        result = ((result >> 8) & 0xff ) | ((result & 0xff) << 8);
    }

    return result; /* ¿¿result¿¿32¿ */
}


unsigned csum_partial(const unsigned char *buff, unsigned len, unsigned sum)
{
    return add32_with_carry(do_csum(buff, len), sum);
}
/*
static inline __sum16 csum_fold(__wsum sum)
{
    __asm__(
            "addl %1, %0            ;\n"
            "adcl $0xffff, %0       ;\n"
            : "=r" (sum)
            : "r" (( u32)sum << 16), "0" (( u32)sum & 0xffff0000)
           );
    return ( __sum16)(~( u32)sum >> 16);
}

static inline __wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr, unsigned short len, unsigned short proto, __wsum sum)
{
    __asm__(
            "addl %1, %0    ;\n"          //addl ¿¿
            "adcl %2, %0    ;\n"          //adcl ¿¿¿¿¿¿
            "adcl %3, %0    ;\n"
            "adcl $0, %0    ;\n"          //¿¿¿¿¿¿¿¿¿¿
            : "=r" (sum)
            : "g" (daddr), "g"(saddr), "g"((len + proto) << 8), "0"(sum)
           );

    return sum;
}

static inline __sum16 csum_tcpudp_magic(__be32 saddr, __be32 daddr, unsigned short len, unsigned short proto, __wsum sum)
{
    return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

static inline __sum16 tcp_v4_check(int len, __be32 saddr, __be32 daddr, __wsum base)
{
    return csum_tcpudp_magic(saddr, daddr, len, IPPROTO_TCP, base);
}

*/
unsigned short ip_fast_csum(unsigned char * iph,
  unsigned int ihl)
{
unsigned int sum;

__asm__ __volatile__(
    "movl (%1), %0 ;\n"
    "subl $4, %2 ;\n"
    "jbe 2f ;\n"
    "addl 4(%1), %0 ;\n"
    "adcl 8(%1), %0 ;\n"
    "adcl 12(%1), %0 ;\n"
"1:     adcl 16(%1), %0 ;\n"
    "lea 4(%1), %1 ;\n"
    "decl %2 ;\n"
    "jne 1b ;\n"
    "adcl $0, %0 ;\n"
    "movl %0, %2 ;\n"
    "shrl $16, %0 ;\n"
    "addw %w2, %w0 ;\n"
    "adcl $0, %0 ;\n"
    "notl %0 ;\n"
"2: ;\n"
/* Since the input registers which are loaded with iph and ihl
  are modified, we must also specify them as outputs, or gcc
  will assume they contain their original values. */
: "=r" (sum), "=r" (iph), "=r" (ihl)
: "1" (iph), "2" (ihl)
: "memory");
return(sum);
}





unsigned short checksum(unsigned short *buf,int nword)
    {
        unsigned long sum;
        
        for(sum=0;nword>0;nword--)
            sum += *buf++;
        sum = (sum>>16) + (sum&0xffff);
        sum += (sum>>16);
        
        return ~sum;
    }

int process_handler(int nic_num)
{
    //printf("in process_handler nic_num   %d\n",nic_num);

    int retval;
    int RecLen;
    unsigned char *resultframe;
    //int resultsize;
    int i;
    unsigned char  MacLocal[6];
    tb[nic_num].skfd = socket(PF_PACKET, SOCK_RAW, htons(SOCK_RAW));

    struct ifreq ifr;

    resultframe=malloc(MAX_PACK);
    if(resultframe==NULL)
    {
        printf("malloc resultframe failed.\r\n");
        return -1;
    }

    while(1)
    {
        //printf("now to receive pkg\r\n");
        memset(resultframe,0,MAX_PACK);
        //RecLen=recvfrom(skfd, resultframe, resultsize, 0, 0, 0);
        RecLen=recv(tb[nic_num].skfd, resultframe, MAX_PACK, 0);
        //nicData[0].bps += RecLen*8;
        if(RecLen==-1)
            break;
        /*
         if(memcmp(resultframe+6,MacLocal,6)==0)
         {
                       printf("Recv Own Pkg Out....\r\n");
                       continue;
         }
          */
        //printf("end to receive pkg   RecLen=%d.\r\n",RecLen);
        pthread_mutex_lock(&mut);
        process_packet(RecLen,resultframe);
        pthread_mutex_unlock(&mut);
#if 0
        if(RecLen>1600)
        {
            for(i=0; i<RecLen; i++)
            {
                printf("%02x ",resultframe[i]);
                if((i+1)%16==0)
                    printf("\r\n");
            }
            printf("\r\n");
            break;
        }
        else
#endif

        }

    close(skfd);
    free(resultframe);


    return 0;
}




get_memoccupy (MEM_OCCUPY *mem) //¶ÔÎÞÀàÐÍgetº¯Êýº¬ÓÐÒ»¸öÐÎ²Î½á¹¹ÌåÀàÅªµÄÖ¸ÕëO
{
    FILE *fd;          
    int n;             
    char buff[256];   
    MEM_OCCUPY *m;
    m=mem;
                                                                                                              
    fd = fopen ("/proc/meminfo", "r"); 
      
    fgets (buff, sizeof(buff), fd); 
	sscanf (buff, "%s %u %s", m->name, &m->total, m->name2); 
   
    fgets (buff, sizeof(buff), fd); //´ÓfdÎÄ¼þÖÐ¶ÁÈ¡³¤¶ÈÎªbuffµÄ×Ö·û´®ÔÙ´æµ½ÆðÊ¼µØÖ·ÎªbuffÕâ¸ö¿Õ¼äÀï 
    sscanf (buff, "%s %u", m->name2, &m->free, m->name2); 
    
    fclose(fd);     //¹Ø±ÕÎÄ¼þfd
}

double cal_cpuoccupy (CPU_OCCUPY *o, CPU_OCCUPY *n) 
{   
    unsigned long od, nd;    
    unsigned long id, sd;
    double cpu_use = 0;   
    
    od = (unsigned long) (o->user + o->nice + o->system +o->idle);//µÚÒ»´Î(ÓÃ»§+ÓÅÏÈ¼¶+ÏµÍ³+¿ÕÏÐ)µÄÊ±¼äÔÙ¸³¸øod
    nd = (unsigned long) (n->user + n->nice + n->system +n->idle);//µÚ¶þ´Î(ÓÃ»§+ÓÅÏÈ¼¶+ÏµÍ³+¿ÕÏÐ)µÄÊ±¼äÔÙ¸³¸øod
      
    id = (unsigned long) (n->user - o->user);    //ÓÃ»§µÚÒ»´ÎºÍµÚ¶þ´ÎµÄÊ±¼äÖ®²îÔÙ¸³¸øid
    sd = (unsigned long) (n->system - o->system);//ÏµÍ³µÚÒ»´ÎºÍµÚ¶þ´ÎµÄÊ±¼äÖ®²îÔÙ¸³¸øsd
    if((nd-od) != 0)
    cpu_use = (double)((sd+id)*10000)/(nd-od); //((ÓÃ»§+ÏµÍ³)¹Ô100)³ý(µÚÒ»´ÎºÍµÚ¶þ´ÎµÄÊ±¼ä²î)ÔÙ¸³¸øg_cpu_used
    //cpu_use = (double)((sd+id)*100)/(nd-od); //((ÓÃ»§+ÏµÍ³)¹Ô100)³ý(µÚÒ»´ÎºÍµÚ¶þ´ÎµÄÊ±¼ä²î)ÔÙ¸³¸øg_cpu_used
    else cpu_use = 0;
    //printf("cpu: %u\n",cpu_use);
    return cpu_use;
}

get_cpuoccupy (CPU_OCCUPY *cpust) //¶ÔÎÞÀàÐÍgetº¯Êýº¬ÓÐÒ»¸öÐÎ²Î½á¹¹ÌåÀàÅªµÄÖ¸ÕëO
{   
    FILE *fd;         
    int n;            
    char buff[256]; 
    CPU_OCCUPY *cpu_occupy;
    cpu_occupy=cpust;
                                                                                                               
    fd = fopen ("/proc/stat", "r"); 
    fgets (buff, sizeof(buff), fd);
    
    sscanf (buff, "%s %u %u %u %u", cpu_occupy->name, &cpu_occupy->user, &cpu_occupy->nice,&cpu_occupy->system, &cpu_occupy->idle);
    
    fclose(fd);     
}

void process_packet(int pkt_len, const u_char *buffer)
{


    unsigned char  MacLocal[6];
    unsigned char  mac_dst[6];
    unsigned char  mac_src[6];
    struct ifreq ifr1;
    struct ethhdr *eth = (struct ethhdr *)buffer;

    memset(mac_dst,0,sizeof(mac_dst));
    memset(mac_src,0,sizeof(mac_src));
    memcpy(mac_dst,buffer,6);
    memcpy(mac_src,buffer+6,6);

    num = gnic.nic_num;
    while(num--)
    {
        if(nicAM[num].tid == (unsigned int)pthread_self())
        {
            memcpy(ifr1.ifr_name, "eth0", sizeof(ifr1.ifr_name));
            ioctl(tb[num].skfd, SIOCGIFHWADDR, &ifr1);
            memset(MacLocal,0,sizeof(MacLocal));
            memcpy((char *)MacLocal, (char *)&ifr1.ifr_hwaddr.sa_data[0], 6);
  //          printf("maclocal=%02x:%02x:%02x:%02x:%02x:%02x\r\n",MacLocal[0],MacLocal[1],MacLocal[2],MacLocal[3],MacLocal[4],MacLocal[5]);
            //printf("mac_src=%02x:%02x:%02x:%02x:%02x:%02x\r\n",mac_src[0],mac_src[1],mac_src[2],mac_src[3],mac_src[4],mac_src[5]);
            //printf("mac_dst=%02x:%02x:%02x:%02x:%02x:%02x\r\n",mac_dst[0],mac_dst[1],mac_dst[2],mac_dst[3],mac_dst[4],mac_dst[5]);
            //if((memcmp(MacLocal,mac_dst,6)==0)||(memcmp(MacLocal,mac_src,6)==0)){
                //printf("111111111\n");
                struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
		TCPHeader_t * tcp_header = (TCPHeader_t *)malloc(sizeof(TCPHeader_t));
        		int ip_len = iph->tot_len;
			switch (iph->protocol) //Check the Protocol and do accordingly...
                    {
                        case 6:  //TCP Protocol
                            {
					
				struct tcphdr *tcph = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
				int src_port = ntohs(tcph->source);
				int dst_port = ntohs(tcph->dest);
				char  host[STRSIZE], uri[BUFSIZE];
					if(dst_port == 80 || src_port == 80 )	 // HTTP GET¿¿
					{
						char *tcp_data = buffer + sizeof(struct ethhdr) + sizeof(struct iphdr)+ sizeof(struct tcphdr);		
						int http_len = ip_len - 40;	 //http ¿¿¿¿
						char *pNext = strstr(tcp_data, " HTTP/1.");
                if (pNext == NULL)
                    return ;
                *pNext = '\0';
                char *http_get = tcp_data + 4;
                int get_len = pNext - http_get;
                    
                    
                char *tmp = strstr(pNext+1, "Host: ");
                if (tmp == NULL)
                    return ;
                char *http_host = tmp + 6;
                char *tmp1 = strchr(http_host, '\r');
                if (tmp1 == NULL)
                    return ;
                *tmp1 = '\0';
                int host_len = tmp1 - http_host;
                printf("Host [%s], host_len [%d]\n", http_host, host_len);	
					if(find(http_host) == 0){
						printf("find host %s\n",http_host);
						printf("mac_src=%02x:%02x:%02x:%02x:%02x:%02x\r\n",mac_src[0],mac_src[1],mac_src[2],mac_src[3],mac_src[4],mac_src[5]);
            					printf("mac_dst=%02x:%02x:%02x:%02x:%02x:%02x\r\n",mac_dst[0],mac_dst[1],mac_dst[2],mac_dst[3],mac_dst[4],mac_dst[5]);
						printf("%s,%d\n", __func__, __LINE__);
            					memset(skb_buf,0,sizeof(skb_buf));
						printf("%s,%d\n", __func__, __LINE__);
						memcpy(skb_buf,buffer,sizeof(struct ethhdr) + sizeof(struct iphdr)+ sizeof(struct tcphdr));
						printf("%s,%d\n", __func__, __LINE__);
						unsigned char *temp_skb = skb_buf;
						struct ethhdr *eth_t = (struct ethhdr *)skb_buf;
						printf("%s,%d\n", __func__, __LINE__);
						memcpy(skb_buf,buffer+6,6);
						printf("%s,%d\n", __func__, __LINE__);
						memcpy(skb_buf+6,buffer,6);
						printf("%s,%d\n", __func__, __LINE__);
						struct iphdr *iph_t = (struct iphdr*)(skb_buf + sizeof(struct ethhdr));
						iph_t->saddr = iph->daddr;	
						iph_t->daddr = iph->saddr;
						printf("%d\n",iph_t->protocol);
						struct tcphdr *tcph_t = (struct tcphdr*)(skb_buf + sizeof(struct ethhdr) + sizeof(struct iphdr));
						tcph_t->dest = tcph->source;
						tcph_t->source = tcph->dest;
							tcph_t->seq = tcph->ack_seq;
							tcph_t->ack_seq = 0;			
						char* error_head = "HTTP/1.0 404 Not Found\r\n";   //¿¿404¿¿head
 						int len = strlen(error_head);
						printf("%s,%d\n", __func__, __LINE__);
						memcpy(skb_buf + sizeof(struct ethhdr) + sizeof(struct iphdr)+sizeof(struct tcphdr),error_head,len);
						printf("%s,%d\n", __func__, __LINE__);
						tcph_t->check = 0;
						csum_partial((char *)tcph_t,sizeof(struct tcphdr), 0);
						printf("%s,%d\n", __func__, __LINE__);
						//tcph_t->check = csum_tcpudp_magic(iph_t->saddr,iph_t->daddr,sizeof(struct tcphdr),iph_t->protocol,0);
						tcph_t->check = csum_tcpudp_magic(iph_t->saddr,iph_t->daddr,sizeof(struct tcphdr),iph_t->protocol,csum_partial((char *)tcph_t,sizeof(struct tcphdr), 0));
						//tcph_t->check = tcp_v4_check(sizeof(struct tcphdr),iph_t->saddr,iph_t->daddr,csum_partial((char *)tcph_t,sizeof(struct tcphdr), 0));
						printf("%s,%d\n", __func__, __LINE__);
						iph_t->check = 0;
						iph_t->check = ip_fast_csum((unsigned char *)iph_t,iph_t->ihl);
						printf("%s,%d\n", __func__, __LINE__);
						int i;
						for(i =0;i<sizeof(struct ethhdr) + sizeof(struct iphdr)+ sizeof(struct tcphdr)+len;i++)
							printf("%02x",buffer[i]);
						printf("\n");
			
						for(i =0;i<sizeof(struct ethhdr) + sizeof(struct iphdr)+ sizeof(struct tcphdr)+len;i++)
							printf("%02x",skb_buf[i]);
						printf("\n");
			
						}else
						printf("find error \n");	
						
				}
			//	}
			    ++nicData[num].tcp_rxpps;
                            nicData[num].tcp_rxbps += pkt_len;
                            //print_tcp_packet(buffer , size);
                            }
				break;

                        case 17: //UDP Protocol
                            ++nicData[num].udp_rxpps;
                            nicData[num].udp_rxbps += pkt_len;
                            //print_udp_packet(buffer , size);
                            break;

                        default: //Some Other Protocol like ARP etc.
                            ++nicData[num].others_rxpps;
                            nicData[num].others_rxbps += pkt_len;
                            break;
                    }

              //  }



            //}

        }
//pthread_mutex_unlock(&mut);
    }

}



void match_http(FILE *fp, char *head_str, char *tail_str, char *buf, int total_len)
{
int i;
int http_offset;
int	 head_len,	tail_len, val_len;
char head_tmp[STRSIZE], tail_tmp[STRSIZE];
//¿¿¿
memset(head_tmp, 0, sizeof(head_tmp));
memset(tail_tmp, 0, sizeof(tail_tmp));
head_len = strlen(head_str);
tail_len = strlen(tail_str);
//¿¿ head_str
http_offset = ftell(fp);	 //¿¿¿HTTP¿¿¿¿¿¿¿¿
while((head_tmp[0] = fgetc(fp)) != EOF)	//¿¿¿¿¿¿
{
if((ftell(fp) - http_offset) > total_len)	 //¿¿¿¿
{
sprintf(buf, "can not find %s \r\n", head_str);
exit(0);
}
if(head_tmp[0] == *head_str)	 //¿¿¿¿¿¿¿¿
{
for(i=1; i<head_len; i++)	 //¿¿ head_str ¿¿¿¿¿
{
head_tmp[i]=fgetc(fp);
if(head_tmp[i] != *(head_str+i))
break;
}
if(i == head_len)	 //¿¿ head_str ¿¿¿¿¿¿¿
break;
}
}
//	printf(¿head_tmp=%s \n¿, head_tmp);
//¿¿ tail_str
val_len = 0;
while((tail_tmp[0] = fgetc(fp)) != EOF)	//¿¿
{
if((ftell(fp) - http_offset) > total_len)	 //¿¿¿¿
{
sprintf(buf,"can not find %s \r\n", tail_str);
exit(0);
}
buf[val_len++] = tail_tmp[0];	 //¿buf ¿¿ value ¿¿¿¿¿ tail_str
if(tail_tmp[0] == *tail_str)	 //¿¿¿¿¿¿¿¿
{
for(i=1; i<tail_len; i++)	 //¿¿ head_str ¿¿¿¿¿
{
tail_tmp[i]=fgetc(fp);
if(tail_tmp[i] != *(tail_str+i))
break;
}
if(i == tail_len)	 //¿¿ head_str ¿¿¿¿¿¿¿
{
buf[val_len-1] = 0;	//¿¿¿¿¿¿¿¿¿
break;
}
}
}
//	printf(¿val=%s\n¿, buf);
fseek(fp, http_offset, SEEK_SET);	//¿¿¿¿¿ ¿¿¿¿¿¿
}
