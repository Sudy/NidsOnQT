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
#include "time.h"
#include "sqlite3.h"


extern sqlite3* sqlitedb;

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

void logToDB(u_char alarmtype,u_char prototype,char* src,char* dst,char* errmsg){

    char* szErrMsg = 0;

    //获取当前的时间
    time_t curtime = time(NULL);

    //准备插入语句
    char pSQL[1024];
    sprintf(pSQL,"INSERT INTO log(time,alarmtype,\
            protype,saddr,daddr,errmsg)\
            VALUES (\"%ld\",\"%d\",\"%d\",\"%s\",\"%s\",\"%s\")",\
                     curtime,alarmtype,prototype,src,dst,errmsg);

    fprintf(stderr,pSQL);
    int rc = sqlite3_exec (sqlitedb,pSQL,0,0,szErrMsg);
    if(SQLITE_OK != rc){
        //fprintf(stderr,"%s",szErrMsg);
        sqlite3_free(szErrMsg);
        return;
    }
}

void responseTCP(struct tcp_stream *a_tcp,u_char alarmtype,u_char prototype,char* errmsg){

    if(NULL == errmsg){
        errmsg = "0";
    }

    switch(alarmtype){

    case ALARM_ALERT:
        break;

    case ALARM_AKILL:
        nids_killtcp(a_tcp);
        break;

    case ALARM_LOG:
        break;
    case ALARM_PASS:
        break;
    }
    char src[30],dst[30];
    struct in_addr netaddr;
    netaddr.s_addr = a_tcp->addr.saddr;
    sprintf(src,"%s:%d",inet_ntoa(netaddr),a_tcp->addr.source);
    netaddr.s_addr = a_tcp->addr.daddr;
    sprintf(dst,"%s:%d",inet_ntoa(netaddr),a_tcp->addr.dest);
    logToDB (alarmtype,prototype,src,dst,errmsg);
}


int responseIP(u_char alarmtype,u_char prototype,\
               char* errmsg,struct ip_header* ip_proto){

    //如果提示的错误信息不为空
    if(NULL != errmsg){

        errmsg = "0";
    }

    switch(alarmtype){
    case ALARM_ALERT:break;
    case ALARM_LOG:break;
    case ALARM_PASS:break;
    default:break;
    }

    char src[30],dst[30];
    if(PROUDP == prototype)
    {
        struct udp_header *udp_proto = (struct udp_header*)(ip_proto + 20);
        sprintf(src,"%s:%d",inet_ntoa(ip_proto->ip_source_address),\
                ntohs(udp_proto->udp_source_port));
        sprintf(dst,"%s:%d",inet_ntoa (ip_proto->ip_destination_address),\
                ntohs (udp_proto->udp_destination_port));
    }else{
        sprintf(src,"%s",inet_ntoa(ip_proto->ip_source_address));
        sprintf(dst,"%s",inet_ntoa (ip_proto->ip_destination_address));
    }
    //记录到数据库中
    logToDB (alarmtype,prototype,src,dst,errmsg);
    return 0;
}

void nids_syslog_new(int type, int errnum, struct ip *iph, void *data)
{
    char saddr[30], daddr[30];
    char buf[128];

    struct host *this_host;
    unsigned char flagsand = 255, flagsor = 0;
    int i;

    switch (type) {

    case NIDS_WARN_IP:
        if (errnum != NIDS_WARN_IP_HDR) {
            strcpy(saddr, int_ntoa(iph->ip_src.s_addr));
            strcpy(daddr, int_ntoa(iph->ip_dst.s_addr));
            //logToDB (ALARM_ALERT,,saddr,daddr,nids_warnings[errnum]);
        }
        break;

    case NIDS_WARN_TCP:
        if (errnum != NIDS_WARN_TCP_HDR){

            sprintf(saddr,"%s:%d",int_ntoa(iph->ip_src.s_addr),\
                    ntohs(((struct tcp_header*) data)->tcp_source_port));
            sprintf(daddr,"%s:%d",int_ntoa(iph->ip_dst.s_addr),\
                    ntohs(((struct tcp_header *) data)->tcp_destination_port));

        }

        else{
            sprintf(saddr,"%s",int_ntoa(iph->ip_src.s_addr));
            sprintf(saddr,"%s",int_ntoa(iph->ip_dst.s_addr));
        }
        logToDB (ALARM_ALERT,PROTCP,saddr,daddr,nids_warnings[errnum]);
        break;

    case NIDS_WARN_SCAN:
        this_host = (struct host *) data;
        sprintf(saddr,"%s",int_ntoa(this_host->addr));
        //扫描的源IP和扫描的IP及端口号

        for (i = 0; i < this_host->n_packets; i++) {

            u_short port = this_host->packets[i].port;
            if(80 != port || 443 != port){
                sprintf(daddr,"%s:%d",int_ntoa(this_host->packets[i].addr),port);

                //获取标志位
                flagsand &= this_host->packets[i].flags;
                flagsor |= this_host->packets[i].flags;

                //扫描的类型
                if (flagsand == flagsor) {
                    switch (flagsand) {
                    case 2:
                        strcpy(buf, "scan type: SYN");
                        break;
                    case 0:
                        strcpy(buf, "scan type: NULL");
                        break;
                    case 1:
                        strcpy(buf, "scan type: FIN");
                        break;
                    default:
                        sprintf(buf, "flags=0x%x", flagsand);
                    }
                }
                else{
                    strcpy (buf, "various flags");
                }
                //记录到数据库中
                logToDB (ALARM_ALERT,PROTCP,saddr,daddr,buf);
            }
        }
        break;
    default:
        fprintf(stderr,"Unknown warning number ?\n");
    }
}
