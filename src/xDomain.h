//================================================================
//    Copyright (C) 2021 INFOGO TECHNOLOGY CO.,LTD
//           File  :  xDomain.h
//         Author  :  ares
//          Email  :  zhouzm@infogo.com.cn
//            Url  :  http://www.infogo.com.cn
//   Create time   :  2021-03-09 14:22
//   Last modified :  2021-03-09 14:22
//    Description  :  
//================================================================
#ifndef __XDOMAIN_H
#define __XDOMAIN_H

#include "xtypes.h"
#include <pthread.h>
#include <pcap.h>
#include <iostream>

class SUBDOMAIN
{
private:
    std::vector<std::string> _addr_list;
    std::string _name;
public:
    SUBDOMAIN();
    SUBDOMAIN(std::string subdomain_name);
    ~SUBDOMAIN();
    int add(std::string);
    int flush();
    int update(std::vector<std::string>);
    void show();
    const std::string& get_name();
};

class DOMAIN
{
    typedef std::vector<SUBDOMAIN> SUBDOMAIN_LIST;
private:
    std::string _template_domain;
    SUBDOMAIN_LIST _sub_domain_list;
public:
    DOMAIN();
    DOMAIN(std::string domain_name);
    ~DOMAIN();
    int add(std::string sub_domain_name);
    int flush();
    int test(std::string);
    void show();
};

#endif
