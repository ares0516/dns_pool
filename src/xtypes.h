//================================================================
//    Copyright (C) 2021 INFOGO TECHNOLOGY CO.,LTD
//           File  :  xtypes.h
//         Author  :  ares
//          Email  :  zhouzm@infogo.com.cn
//            Url  :  http://www.infogo.com.cn
//   Create time   :  2021-03-08 10:19
//   Last modified :  2021-03-08 20:11
//    Description  :  
//================================================================
#ifndef __TYPES_H
#define __TYPES_H

#include <string>
#include <vector>
#include <set>
#include <arpa/inet.h>

typedef char            s8;
typedef short           s16;
typedef int             s32;
typedef unsigned char   u8;
typedef unsigned short  u16;
typedef unsigned int    u32;



typedef std::string                 VALUE;  // IP
typedef std::vector<VALUE>          VALUES; //

typedef std::string                 DEV;
typedef std::vector<DEV>    DEV_LIST;


typedef struct packet_analyzer
{

}PKT_ANA_T;


// RFC
// 禁止优化结构体成员位置
#pragma pack (push)
#pragma pack (1)
typedef struct ether_header
{
    u8 ether_dst[6];
    u8 ether_src[6];
    u16 ether_type;
}ETHER_HEADER_T;

typedef struct ip_header
{
    u8 header_length:4;
    u8 version:4;
    u8 tos;
    u16 total_length;
    u16 id;
    u16 offset;
    u8 ttl;
    u8 protocol;
    u16 checksum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
}IP_HEADER_T;

typedef struct udp_header
{
    u16 udp_source_port;
    u16 udp_destination_port;
    u16 udp_length;
    u16 udp_checksum;
}UDP_HEADER_T;

typedef struct dns_packet
{
    u16 dns_trans_id;
    u16 dns_flag;
    u16 dns_question;
    u16 dns_answer;
    u16 dns_authority;
    u16 dns_additional;
    u8 *dns_data;
}DNS_PKT_T;
#pragma pack (pop)



#endif
