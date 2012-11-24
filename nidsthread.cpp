#include "nidsthread.h"

extern "C"{
#include "nids.h"
#include "response.h"
#include "ids.h"
}
NidsThread::NidsThread(){
}

void NidsThread::run ()
{

    struct nids_chksum_ctl temp;
    temp.netaddr = 0;
    temp.mask = 0;
    temp.action = 1;
    nids_register_chksum_ctl(&temp,1);

    nids_params.syslog = (void (*)())nids_syslog_new;

    if (!nids_init ())
    {
        fprintf(stderr,"%s\n",nids_errbuf);
        return;
    }
    nids_register_tcp ((void*)tcp_callback);
    nids_register_ip_frag((void*)ip_callback);

    nids_run ();
}
