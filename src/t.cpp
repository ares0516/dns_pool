#include <stdio.h>
#include <string>
#include <string.h>
#include <vector>
#include <unistd.h>
#include <stdlib.h>

typedef std::string			DEV;
typedef std::vector<DEV>    DEV_LIST;
#pragma pack (1)
typedef struct packet
{
    //unsigned short aa;
    //unsigned short bb;
    char* ptr;
}PACK_T;

int main()
{
	std::vector<std::string> list;

	std::string str1("aaaa");

	DEV_LIST devs;
	DEV dev("eth1");
	list.emplace_back(str1);

	devs.emplace_back(dev);

    char *pbuf = (char *)malloc(100);
    memset(pbuf,0,100);
    strncpy(pbuf,"abcdefghigklmnopqrstuvwxyz",24);

	PACK_T *p = NULL;
	
	p = (PACK_T*)pbuf;

	//printf("[%02x]\n",p->aa);
	//printf("[%02x]\n",p->bb);

    char *ps = (char *)&(p->ptr);
	printf("[%c]\n",*ps);
	ps++;
	printf("[%c]\n",*ps);
	ps++;
	printf("[%c]\n",*ps);
}
