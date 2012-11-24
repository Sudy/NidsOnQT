#ifndef RESPONSE_H
#define RESPONSE_H
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>

#include "nids.h"
#include "protoheader.h"

    int responseIP(u_char alarmtype,u_char prototype,char* errmsg,struct ip_header* ip_protocol);
    void responseTCP(struct tcp_stream *a_tcp,u_char alarmtype,u_char prototype,char* errmsg);
    void nids_syslog_new(int type, int errnum, struct ip *iph, void *data);

#endif // RESPONSE_H
