//================================================================
//    Copyright (C) 2021 INFOGO TECHNOLOGY CO.,LTD
//           File  :  xFilter.cpp
//         Author  :  ares
//          Email  :  zhouzm@infogo.com.cn
//            Url  :  http://www.infogo.com.cn
//   Create time   :  2021-03-08 16:07
//   Last modified :  2021-03-08 20:48
//    Description  :  
//================================================================
#include "xFilter.h"
#include "unistd.h"
#include <iostream>
#include <pthread.h>
#include <pcap.h>
#include <arpa/inet.h>

FILTER::FILTER()
{
}

FILTER::~FILTER()
{

}

// 域名解析线程
void* FILTER::_resolve_func(void* args)
{
    FILTER *pf = (FILTER*)args;

    while(1)
    {
        for(DOMAIN_LIST::iterator iter = pf->_domain_match_list.begin(); iter != pf->_domain_match_list.end(); ++iter)
        {
            //printf("resolve domain=>[%s]\n",iter->name().c_str());
            iter->resolve();
        }
        sleep(5);
    }

}

// 数据包解析函数，用于pcap_loop回调时处理数据包
void FILTER::_pkt_handler_callback_func(pcap_t *args, struct pcap_pkthdr *pCapHeader, const u8 *pData)
{
    FILTER *pf = (FILTER*)args;

    ETHER_HEADER_T *ether_header = NULL;
    u16 ether_type = 0;
    u8 *puVlanBuf = NULL;
    u32 uVlanLen = 0;
    
    UDP_HEADER_T *udp_header = NULL;
    u16 src_port,dst_port;

    DNS_PKT_T *dns_pkt = NULL;

    u32 uCapLen = pCapHeader->caplen;


    //std::cout<<"cap ---------!!!!"<<pf->_dev<<std::endl;

    u32 ulen = pCapHeader->caplen;

    if(!pCapHeader || !pData)
    {
        return;
    }

    // process eth_header + vlan_tag
    ether_header = (ETHER_HEADER_T *)pData;
    ether_type = ntohs(ether_header->ether_type);

    // unpack vlan
    puVlanBuf = (u8*)(pData + 12);
    while(0x8100 == ether_type)
    {
        puVlanBuf += 4;
        uVlanLen += 4;
        if(uCapLen < (sizeof(ETHER_HEADER_T) + uVlanLen))
        {
            return;
        }
        ether_type = ntohs(*(u16 *)puVlanBuf);
    }
    // ip processing

    // udp processing
    udp_header = (UDP_HEADER_T *)(pData + sizeof(ETHER_HEADER_T) + uVlanLen + sizeof(IP_HEADER_T));
    src_port = ntohs(udp_header->udp_source_port);
    dst_port = ntohs(udp_header->udp_destination_port);
    //printf("----[%d][%d][%d][%x]\n",src_port,dst_port,ntohs(udp_header->udp_length),ntohs(udp_header->udp_checksum));
    if(53 == dst_port)
    {
        std::cout<<"dns query detected !"<<std::endl;

        dns_pkt = (DNS_PKT_T *)(pData + sizeof(ETHER_HEADER_T) + uVlanLen + sizeof(IP_HEADER_T) + sizeof(UDP_HEADER_T));

        //standrd query
        //printf("````````[0x%04x][0x%04x]\n",dns_pkt->dns_trans_id,dns_pkt->dns_flag);
        if(0x0100 == ntohs(dns_pkt->dns_flag))
        {
            //printf("`````0```\n");
            u8 domain[128] = {0};
            u8 *dns_query = NULL;
            u16 *dns_query_type = NULL;
            u8 idx = 0;;

            dns_query = (u8 *)&(dns_pkt->dns_data);
            while(*dns_query)
            {
                // printf("`````0```\n");
                domain[idx] = *dns_query;
                if(*dns_query < 0x30)
                {
                    // printf("%c\n",'.');
                    domain[idx] = '.';
                }
                else
                {
                    // printf("%c\n",*dns_query);
                    domain[idx] = *dns_query;
                }
                dns_query++;
                idx++;
            }
            dns_query_type = (u16 *)(dns_query + 2);
            
            // // A record query
            if(0x0001 == *dns_query_type)
            {
                printf("collect domain=>[%s]\n",domain);
            //     // std::string srt11 = (char *)domain;
            //     // std::cout<<"A : "<< srt11 <<std::endl;
                std::string tmp_domain((char *)domain);

                pf->add_sub_domain(tmp_domain);
            }
        }
        //printf("`````1```\n");
    }
    //printf("`````2```\n");
}

// 流量监听线程
void* FILTER::_cap_func(void * args)
{
    FILTER *pf = (FILTER*)args;
    // while(1)
    // {
    //     std::cout<<pf->_dev<<std::endl;
    //     sleep(1);
    // }
    s8 errbuf[PCAP_ERRBUF_SIZE] = {0};
    struct bpf_program sfFilter = {0};
    pcap_t *pCapDev = NULL;
    while(1)
    {
        pCapDev = pcap_open_live(pf->_dev.c_str(), 65535, 1, 0, errbuf);
        if(!pCapDev)
        {
            std::cout<<"open error!"<<std::endl;
            break;
        }
        pcap_compile(pCapDev, &sfFilter, "udp port 53", 1, PCAP_NETMASK_UNKNOWN);
        
        pcap_setfilter(pCapDev,&sfFilter);
        
        std::cout<<"dev start"<<std::endl;
        
        pcap_loop(pCapDev, -1, (pcap_handler)_pkt_handler_callback_func, (u8*)args);
        // pcap_loop(pCapDev, -1, (pcap_handler)dns_protocol_packet_callback, (u8*)args);

        pcap_close(pCapDev);
        std::cout<<"dev close"<<std::endl;
    }
}

DEV FILTER::interface_get()
{
    return _dev;
}

int FILTER::start()
{
    pthread_create(&_cap_handler, NULL, _cap_func, (void*)this);

    pthread_create(&_resolve_handler, NULL, _resolve_func, (void*)this);

    //pthread_create(&_sync_handler, NULL, _sync_func, (void*)this);

    //pthread_create(&_debug_thread)
}

int FILTER::interface_add(DEV &dev)
{
    _dev = dev; 
    std::cout<<_dev<<std::endl;
}

// 添加二级域名到解析器域名匹配列表
int FILTER::add_domain(string& name)
{
    const char &cfirst = name.front();
    if('.' == cfirst)
    {
        name.erase(0,1);
        Domain domain(name);
        _domain_match_list.emplace_back(domain);
    }
    return 0;
}

int FILTER::add_sub_domain(string& name)
{
    // 依次调用待匹配域名的匹配器（try_match）对于子域名进行添加
    for(DOMAIN_LIST::iterator iter = _domain_match_list.begin(); iter != _domain_match_list.end(); ++iter)
    {
        iter->try_match(name);
    }
}

int FILTER::show()
{
    for(DOMAIN_LIST::iterator iter = _domain_match_list.begin(); iter != _domain_match_list.end(); ++iter)
    {
        iter->show();
    }
}

// int FILTER::interface_add(DEV_LIST &list)
// {
//     // for(DEV_LIST::const_iterator iter = list.begin(); iter != list.end(); ++iter)
//     // {
//     //     _devs.emplace_back(iter);
//     //     std::cout<<_devs.size()<<std::endl;
//     // }
// }

// int FILTER::interface_show()
// {
//     for(DEV_LIST::const_iterator iter = _devs.begin(); iter != _devs.end(); ++iter)
//     {
//         std::cout<<*iter<<std::endl;
//     } 
// }
