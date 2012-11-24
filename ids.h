#ifndef IDS_H
#define IDS_H
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>

#include "nids.h"

struct pattern{
    u_char alarmtype; //预警类型
    u_char prototype;
    char* content; //内容
    u_int length;  //内容长度
    char*   errmsg;   //预警信息
};

u_int getMaskBit(u_int prefix);
void ip_callback(struct ip *a_packet, int len);
void tcp_callback (struct tcp_stream *a_tcp, struct pattern** param);
//void nids_syslog_new(int type, int errnum, struct ip *iph, void *data);

#endif // IDS_H
