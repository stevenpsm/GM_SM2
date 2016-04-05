// Base64.h: interface for the CBase64 class.
//
//////////////////////////////////////////////////////////////////////


#ifndef _BASE64_H
#define _BASE64_H

#include <stdio.h>


enum Base64Option
{
	BASE64_NeedCRLF = 1
};

int base64_decode( const char *base64_data,long base64_size,unsigned char *bin_data,unsigned long *bin_size );
int base64_encode( unsigned char * bin_data, long bin_size, char * base64_data,unsigned long * base64_size,int Mode );

int Base64EncodeSize(int iSize, int mode) ;

//获取Base64解码长度 
int Base64DecodeSize(int iSize);

#endif // !_BASE64_H
