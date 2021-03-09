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


SUBDOMAIN::SUBDOMAIN()
{

}

SUBDOMAIN::SUBDOMAIN(std::string sub_domain_name)
{
    _name = sub_domain_name;
}

SUBDOMAIN::~SUBDOMAIN()
{
    
}

void SUBDOMAIN::show()
{
    for(std::vector<std::string>::const_iterator iter = _addr_list.begin(); iter != _addr_list.end(); ++iter)
    {
        std::cout << *iter<< std::endl;
    }
}

const std::string& SUBDOMAIN::get_name()
{
    return _name;
}

DOMAIN::DOMAIN()
{

}

DOMAIN::DOMAIN(std::string domain_name)
{
    _template_domain = domain_name; 
}

DOMAIN::~DOMAIN()
{

}

int DOMAIN::add(std::string sub_domain_name)
{
    SUBDOMAIN sub_domain(sub_domain_name);
    _sub_domain_list.emplace_back(sub_domain);
    printf("====[%s] add [%s]\n",_template_domain.c_str(), sub_domain_name.c_str());
    return 0;
}

void DOMAIN::show()
{
    printf("DOMAIN:[%s]\n",_template_domain.c_str());
    for(SUBDOMAIN_LIST::iterator iter = _sub_domain_list.begin(); iter != _sub_domain_list.end(); ++iter)
    {
        printf("    SUBDOMAIN:[%s]\n",iter->get_name().c_str());
        iter->show();
    }
}

int DOMAIN::test(std::string name)
{
    std::string::size_type idx;
    idx = name.find(_template_domain);
    if(idx == std::string::npos)
    {
        // not find
    }
    else
    {
        add(name);
    }
    
}