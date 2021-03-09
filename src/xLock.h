//================================================================
//    Copyright (C) 2021 INFOGO TECHNOLOGY CO.,LTD
//           File  :  xLock.h
//         Author  :  ares
//          Email  :  zhouzm@infogo.com.cn
//            Url  :  http://www.infogo.com.cn
//   Create time   :  2021-03-08 16:25
//   Last modified :  2021-03-08 17:06
//    Description  :  
//================================================================
#ifndef __XLOCK_H
#define __XLOCK_H

#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

class xLock
{
private:
    pthread_mutex_t mMutex;
public:
    inline xLock()
    {
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        int ret = pthread_mutex_init(&mMutex, &attr);
        if(ret != 0)
        {
            fprintf(stderr,"pthread_mutex_init error!\n\r", ret);
        }
    };

    inline ~xLock()
    {
        pthread_mutex_destroy(&mMutex);
    };

    inline Enter()
    {
        pthread_mutex_lock(&mMutex);
    };

    inline Leave()
    {
        pthread_mutex_unlock(&mMutex);
    };
};

class CLockUser
{
public:
    inline CLockUser(xLock &lock):mlock(lock)
    {
        mlock.Enter();
    };
    inline ~CLockUser()
    {
        mlock.Leave();
    };
private:
    xLock& mLock;
};

#define XLOCK(T) CLockUser lock(T)

#endif
