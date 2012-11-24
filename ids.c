#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>


#include "protoheader.h"
#include "nids.h"
#include "rule.h"
#include "response.h"
#include "ids.h"
//#include "pthread.h"


#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))



extern struct ruleNode* ruleTCP;
extern struct ruleNode* ruleIP;
//extern  pthread_mutex_t mutexTCP;
//extern  pthread_mutex_t mutexIP;

/********************************************************
  计算子网掩码的位数
 ********************************************************/
u_int getMaskBit(u_int prefix){

    int i = 0;
    while (((prefix)& 0x1) == 0){
        i++;
        printf("%d\n",i);
        prefix = prefix>>1;
    }
    return 32 - i;
}

//判断IP是否属于某个网段
//参数需要比较的IP，网段IP，以及掩码的位数
char ParseCIDRBan(unsigned int IP, unsigned int Mask, unsigned int MaskBits)
{
    // CIDR bans are a compacted form of IP / Submask
    // So 192.168.1.0/255.255.255.0 would be 192.168.1.0/24
    // IP's in the 192.168.1.x range would be hit, others not.
    unsigned char * source_ip = (unsigned char*)&IP;
    unsigned char * mask = (unsigned char*)&Mask;


    int full_bytes = MaskBits / 8;
    int leftover_bits = MaskBits % 8;


    //检查掩码的有效性
    if( MaskBits > 32 )
        return 0;

    // this is the table for comparing leftover bits
    static  unsigned char leftover_bits_compare[9] = {
        0x00,			// 00000000
        0x80,			// 10000000
        0xC0,			// 11000000
        0xE0,			// 11100000
        0xF0,			// 11110000
        0xF8,			// 11111000
        0xFC,			// 11111100
        0xFE,			// 11111110
        0xFF,			// 11111111 - This one isn't used
    };

    //首先判断其网络号是否相同
    if( full_bytes > 0 )
    {
        if( memcmp( source_ip, mask, full_bytes ) != 0 )
            return 0;
    }
    //再与主机号进行比较
    if( leftover_bits > 0 )
    {
        if( ( source_ip[full_bytes] & leftover_bits_compare[leftover_bits] ) !=
                ( mask[full_bytes] & leftover_bits_compare[leftover_bits] ) )
        {
            // 其中有一项不吻合便不在一个网段上
            return 0;
        }
    }
    //所有的都吻合
    return 1;
}

//判断IP是否与规则集中的相同
char checkIP(u_int saddr,u_int daddr,struct ruleNode* ruleTmp){
    char src = 0;
    char dst = 0;
    if(IPANY == ruleTmp->data.saddr){
        src = 1;
    }else{

        //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        //mask smask?
        src = ParseCIDRBan(saddr,ruleTmp->data.saddr,ruleTmp->data.smask);
    }
    //如果源不符合就不用判断目的
    if(1 == src ){
        if(IPANY == ruleTmp->data.daddr){
            dst = 1;
        }else{
            dst = ParseCIDRBan(daddr,ruleTmp->data.daddr,ruleTmp->data.dmask);
        }
    }
    return (src&&dst);
}



void icmp_callback(const char *packet_content)
{
    struct ip_header *ip_protocol;
    ip_protocol = (struct ip_header*)(packet_content);
    u_int saddr = ip_protocol->ip_source_address.s_addr;
    u_int daddr = ip_protocol->ip_destination_address.s_addr;

    //pthread_mutex_lock (&mutexIP);
    struct ruleNode* ruleTmp = ruleIP->next;

    while(NULL != ruleTmp){
        //如果命中
        if(checkIP(saddr,daddr,ruleTmp)){
            //处理函数
            responseIP(ruleTmp->data.alarmtype,ruleTmp->data.protype,\
                       ruleTmp->data.errmsg,ip_protocol);
            break;
        }
        ruleTmp =  ruleTmp->next;
    }
  //pthread_mutex_unlock (&mutexIP);
    return ;
}


void udp_callback(char *packet_content)
{
    struct udp_header *udp_protocol;
    struct ip_header *ip_protocol;

    //获得IP地址等信息
    ip_protocol = (struct ip_header*)(packet_content);
    u_int saddr = ip_protocol->ip_source_address.s_addr;
    u_int daddr = ip_protocol->ip_destination_address.s_addr;

    u_short srcport = 0;
    u_short dstport = 0;

    udp_protocol = (struct udp_header*)(packet_content + 20);

    /* 获取源端口号 */
    srcport = ntohs(udp_protocol->udp_source_port);
    /* 获取目的端口号 */
    dstport = ntohs(udp_protocol->udp_destination_port);

    //pthread_mutex_lock (&mutexIP);
    struct ruleNode* ruleTmp = ruleIP->next;

    while(NULL != ruleTmp){

        if(PORTANY == ruleTmp->data.sport){
            srcport = 1;
        }else{
            srcport = (srcport == ruleTmp->data.sport);
        }
        //如果源端口符合,判断目的端口
        if(1 == srcport){
            if(PORTANY == ruleTmp->data.dport){
                dstport = 1;
            } else{
                dstport = (dstport == ruleTmp->data.dport);
            }
        }
        //如果源地址符合，端口符合，目的地址符合，目的端口符合
        if(srcport && dstport && checkIP(saddr,daddr,ruleTmp)){
            //如果有需要匹配的内容
            if("0" != ruleTmp->data.content){
                //获得内容的长度
                int conLen = strlen(ruleTmp->data.content);
                //获得数据部分
                const char* content = packet_content + 20 +
                        sizeof(struct udp_header);
                //获得负载的长度
                int datalen = strlen(content);
                
                //如果负载长度不够
                if(datalen < conLen){
                    return;
                }
                int i = 0;
                for(i = 0; i <= datalen - conLen;i++){
                    //如果有匹配的模式
                    if (!memcmp (ruleTmp->data.content, content + i, conLen)){
                        responseIP(ruleTmp->data.alarmtype,ruleTmp->data.protype,\
                                   ruleTmp->data.errmsg,ip_protocol);
                        return;
                    }
                }
            }
            responseIP(ruleTmp->data.alarmtype,ruleTmp->data.protype,\
                       ruleTmp->data.errmsg,ip_protocol);
            break;
        }
        //如果没有内容要匹配，也需要处理
        ruleTmp = ruleTmp->next;
    }
    //pthread_mutex_unlock (&mutexIP);

}
void ip_protocol_packet_callback(char *packet_content)
{
    struct ip_header *ip_protocol;
    ip_protocol = (struct ip_header*)(packet_content);

    switch (ip_protocol->ip_protocol) /* 判断上层协议类型 */
    {
    case 17:
        udp_callback(packet_content);
        break;
    case 1:
        icmp_callback(packet_content);
        break;
    default:
        break;
    }

}

void ip_callback(struct ip *a_packet, int len)
{
    ip_protocol_packet_callback((char*)a_packet);
    /* 调用分析IP协议的函数 */
}

//判断该流是不是我们需要的
int check(struct tcp_stream *a_tcp,struct pattern** param){

    //pthread_mutex_lock(&mutexTCP);
    struct ruleNode* rulePointer = ruleTCP->next;
    struct pattern* ptn = *param;
    
    char srcport = 0;
    char dstport = 0;
    while(NULL != rulePointer){

        if(PORTANY == rulePointer->data.sport){
            srcport = 1;
        }else{
            srcport = (a_tcp->addr.source == rulePointer->data.sport);
        }
        //源端口匹配上了
        if(1 == srcport){
            if(PORTANY == rulePointer->data.dport){
                dstport = 1;
            } else{
                dstport = (a_tcp->addr.dest == rulePointer->data.dport);
            }
        }
        //如果源地址符合，端口符合，目的地址符合，目的端口符合
        if(srcport && dstport && checkIP(a_tcp->addr.saddr,\
                                         a_tcp->addr.daddr,rulePointer) ){
            //保存预警类型
            ptn->alarmtype = rulePointer->data.alarmtype;
            ptn->prototype =  rulePointer->data.protype;

            //如果规则的content不为空，即有关键信息
            if("0" != rulePointer->data.content){
                ptn->length = strlen(rulePointer->data.content);
                ptn->content = (char*)malloc(ptn->length + 1);
                strcpy(ptn->content,rulePointer->data.content);
            }
            //如果错误信息不为空
            if("0" != rulePointer->data.errmsg){
                ptn->errmsg = (char*)malloc(strlen(rulePointer->data.errmsg) + 1);
                strcpy(ptn->errmsg,rulePointer->data.errmsg);
            }
            return 1;
        }
        rulePointer = rulePointer->next;
    }
    //表示没有匹配的项
    return 0;
}



//我们需要传递content参数,用于比较pattern
void tcp_callback (struct tcp_stream *a_tcp, struct pattern** param)
{

    struct half_stream *hlf;
    u_int datalen = 0;//data area length
    u_int i = 0;

    if (a_tcp->nids_state == NIDS_JUST_EST){
        struct pattern* ptn = (struct pattern*)\
                malloc(sizeof(struct pattern));
        ptn->content = NULL;
        ptn->errmsg = NULL;
        ptn->length = 0;
        *param = ptn;

        //表示是我们关心的数据
        if(1 == check(a_tcp,param)){
            a_tcp->server.collect++;
            if(ALARM_AKILL == (*param)->alarmtype)
            {
                nids_killtcp (a_tcp);
                responseTCP(a_tcp,(*param)->alarmtype,(*param)->prototype,\
                            (*param)->errmsg);
                nids_free_tcp_stream (a_tcp);
                return;
            }
        }else{
            free(ptn);
        }
        return;
    }
    if (a_tcp->nids_state != NIDS_DATA){
        free (*param);
        return;
    }

    hlf = &a_tcp->server;
    datalen = hlf->count - hlf->offset;

    //如果长度不为空
    if(0 != (*param)->length){
        fprintf(stderr,"yes");
        //如果数据长度不够,先放入缓存,然后再进行比较
        if (datalen < (*param)->length)
        {
            nids_discard (a_tcp, 0);
            return;
        }

        //进行比较
        for (i = 0; i <= datalen - (*param)->length; i++){
            //如果有匹配的模式
            if (0 == memcmp ((*param)->content, hlf->data + i, (*param)->length)) {
                fprintf(stderr,"i'm coming!");
                responseTCP(a_tcp,(*param)->alarmtype,(*param)->prototype,\
                            (*param)->errmsg);
                return;
            }
        }
        //如果没有吻合的字符串,比较完将剩下的部分继续放入缓存
        if (i > datalen - (*param)->length)
        {
            // retain PATLEN bytes in buffer
            nids_discard (a_tcp, datalen -  (*param)->length);
            return;
        }
    }
}






