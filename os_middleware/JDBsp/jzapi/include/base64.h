/*
 * base64
 * 2017-09-18
 * 盛耀微科技
 * wxj@glinkwin.com
 */

#ifndef __BASE64_HH__
#define __BASE64_HH__

int base64_enc(char* dst,u8* src,int srclens);
int base64_dec(char* dst,u8* src,int srclens);

#endif
