//================================================================
//    Copyright (C) 2021 INFOGO TECHNOLOGY CO.,LTD
//           File  :  xFilter.h
//         Author  :  ares
//          Email  :  zhouzm@infogo.com.cn
//            Url  :  http://www.infogo.com.cn
//   Create time   :  2021-03-08 14:25
//   Last modified :  2021-03-08 20:47
//    Description  :  common packet filter
//================================================================
#ifndef __FILTER_H
#define __FILTER_H

#include "xtypes.h"
#include "xDomain.h"
#include <pthread.h>
#include <pcap.h>





typedef std::vector<DOMAIN> DOMAIN_LIST;
class FILTER
{
private:
    DOMAIN_LIST _domain_list;
    DEV_LIST    _devs;   //　监听端口列表
    DEV         _dev;
    pthread_t   _thread_handler;
    static void*    _listen_func(void* args);
    static void     _pkt_handler_func(pcap_t *pCapDev, struct pcap_pkthdr *pCapHeader, const u8 *pBuf);
public:
    FILTER();
    ~FILTER();
    int start();
    int interface_add(DEV &dev);
    DEV interface_get();
    //int interface_add(DEV_LIST &dev);
    //int interface_del(DEV &dev);
    int interface_del(DEV_LIST &list);
    //int interface_get(DEV_LIST &list);
    int interface_show();
    int domain_show();
    int domain_add(std::string);
    int subdomain_add(std::string);
    int destory();
};

#endif
