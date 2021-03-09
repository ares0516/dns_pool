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
#include <map>
#include <vector>
#include <resolv.h>
#include <netdb.h>

using namespace std;

class Domain
{
typedef map<string,vector<string>> LIST;
typedef vector<string> ADDR_LIST;
private:
    string _name;   // 域名
    LIST _sub_list; // 子域名列表
public:
    Domain();
    Domain(const string& domain_name);
    ~Domain();
    int add_sub(const string& sub_domain_name);
    int try_match(const string&);
    void show();
    int resolve();
    const string& name();
};

#endif