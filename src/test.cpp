//================================================================
//    Copyright (C) 2021 INFOGO TECHNOLOGY CO.,LTD
//           File  :  test.cpp
//         Author  :  ares
//          Email  :  zhouzm@infogo.com.cn
//            Url  :  http://www.infogo.com.cn
//   Create time   :  2021-03-08 19:17
//   Last modified :  2021-03-08 20:45
//    Description  :  
//================================================================
#include "xFilter.h"
#include <iostream>
#include "unistd.h"
int main()
{
    FILTER fil;
    DEV dev("wlp0s20f3");

    std::string str1(".baidu.com");
    std::string str2(".qq.com");

    fil.add_domain(str1);
    fil.add_domain(str2);

    fil.interface_add(dev);
    fil.start();

    
    

     while(1)
     {
        //std::cout<<"main"<<std::endl;
        fil.show();
        sleep(10);
     }

    return 0;
}
