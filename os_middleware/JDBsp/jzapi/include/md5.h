//
//  md5.h
//  ssudp
//
//  Created by wxj on 15/6/1.
//  Copyright (c) 2015年 glink. All rights reserved.
//

#ifndef __jz__md5__
#define __jz__md5__


#include "typedef.h"

typedef   struct
{
    u32   state[4];
    u32   count[2];
    unsigned   char   buffer[64];
}MD5_CTX;

void   MD5Init(MD5_CTX *);
void   MD5Update(MD5_CTX *,u8*,u32);
void   MD5Final(u8 [16], MD5_CTX *);

void MD5(u8 * md5buf,u8 * srcBuf,int lens);

#endif
