//================================================================
//    Copyright (C) 2021 INFOGO TECHNOLOGY CO.,LTD
//           File  :  xDomain.cpp
//         Author  :  ares
//          Email  :  zhouzm@infogo.com.cn
//            Url  :  http://www.infogo.com.cn
//   Create time   :  2021-03-09 14:22
//   Last modified :  2021-03-09 14:22
//    Description  :  
//================================================================
#include "xDomain.h"

Domain::Domain()
{

}

// 初始化并设置名称
Domain::Domain(const string& domain_name)
{
    _name = domain_name; 
}

Domain::~Domain()
{

}

const string& Domain::name()
{
    return _name;
}

// 解析当前域的子域名
int Domain::resolve()
{
    struct hostent *host;
    s32 iCnt = 0;

    if(_sub_list.empty())
    {
        return 0;
    }

    res_init();
    
    for(auto map_iter = _sub_list.begin(); map_iter != _sub_list.end(); ++map_iter)
    {
        printf("Resolve---->SUBDOMAIN:[%s] =>",map_iter->first.c_str());
        host = gethostbyname(map_iter->first.c_str());
        if(NULL == host)
        {
            continue;
        }
        else
        {
            s8 **n_addr;
            u32 ip;
            for(n_addr = host->h_addr_list; *n_addr; n_addr++)
            {
                ip = *((u32 *)(*n_addr));
                if(ip)
                {
                    char addr[18] = {0};
                    inet_ntop(AF_INET, &ip, addr, sizeof(addr));
                    printf("[%s]",addr);
                    iCnt++;
                    map_iter->second.emplace_back(string(addr));
                }
            }
        }
        printf("\n");
    }
    return iCnt;
}

// 添加子域名
int Domain::add_sub(const string& sub_domain_name)
{
    //LIST::iterator iter;

    auto search = _sub_list.find(sub_domain_name);
    if(search == _sub_list.end())    // not found
    {
        ADDR_LIST addr_list;
        _sub_list.emplace(make_pair(sub_domain_name,addr_list));
    }
    
    return 0;
}

// 
void Domain::show()
{
    printf("DOMAIN:[%s]\n",_name.c_str());
    for(auto map_iter = _sub_list.begin(); map_iter != _sub_list.end(); ++map_iter)
    {
        printf("---->SUBDOMAIN:[%s]\n",map_iter->first.c_str());

        for(auto vec_iter = map_iter->second.begin(); vec_iter != map_iter->second.end(); ++vec_iter)
        {
            printf("-------->ADDR:[%s]\n",(*vec_iter).c_str());
        }
    }
}

// 使用三级(+)域名尝试匹配二级域名, 匹配成功则加入该二级域名的子域名列表
int Domain::try_match(const string& name)
{
    string::size_type idx;
    idx = name.find(_name);
    if(idx == string::npos)
    {
        // not find
    }
    else
    {
        name.erase(0,1);    // 去除起始位置'.'
        add_sub(name);
    }
    
}