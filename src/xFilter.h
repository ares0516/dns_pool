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





typedef std::vector<Domain> DOMAIN_LIST;
class FILTER
{
private:
    DOMAIN_LIST _domain_match_list;
    //DEV_LIST    _devs; // TODO: 下一个版本加入多端口支持
    DEV         _dev;
    pthread_t   _cap_handler;
    pthread_t   _resolve_handler;
    pthread_t   _sync_handler;
    static void*    _sync_func(void* args);
    static void*    _resolve_func(void* args);
    static void*    _cap_func(void* args);
    static void     _pkt_handler_callback_func(pcap_t *pCapDev, struct pcap_pkthdr *pCapHeader, const u8 *pBuf);
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
    int show();
    int add_domain(string&);
    int add_sub_domain(string&);
    int destory();
};

#endif
