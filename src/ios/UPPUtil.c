//
//  UPPUtil.c
//  xFace
//
//  Created by hejp raul on 12-5-23.
//  Copyright (c) 2012年 Polyvi Inc. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/**
 HEX编码 将数组转换成16进制字符串.
 如0x12 0x2A 0x01 转换为"122A01"
 @param data    被编码的数据
 @param len     被编码数据长度
 @param des     编码后的数据
 @returns void
 */
void RSA_hexEncode(char* data, int len, char* des)
{
	des[0] = 0;
	for (int i = 0; i < len; i++)
    {
		char c = data[i];
		unsigned int hi = ((c & 0xF0)>>4) & 0x0F;
        unsigned int low = c & 0x0F;
		sprintf(des, "%s%X", des,hi);
		sprintf(des, "%s%X", des,low);
	}
}

/**
 HEX解码 将成16进制字符串转换成数组.
 如"122A01"转换为0x12 0x2A 0x01
 @param data    被解码的数据
 @param len     被解码数据长度
 @param des     解码后的数据
 @returns 成功返回解码后长度，否则返回(-1)
 */
int RSA_hexDecode(char* data, int len, char* des)
{
	int l = len;
	char* p = des;
	int offset = 0;
	for (int i = 0; i < l; i+=2)
    {
		unsigned char hi = data[i];
        unsigned char low = data[i+1];
		if( hi>='0' && hi<='9')
        {
            hi -= '0';
        }
        else if(hi>='A' && hi<='Z')
        {
            hi -= 'A';
            hi += 10;
		}
        else if(hi>='a' && hi<='z')
        {
			hi -= 'a';
            hi += 10;
		}
        else
        {
            return -1;
        }

		if( low>='0' && low<='9')
        {
            low -= '0';
        }
        else if(low>='A' && low<='Z')
        {
            low -= 'A';
            low += 10;
		}
        else if(low>='a' && low<='z')
        {
			low -= 'a';
            low += 10;
		}
        else
        {
			return -1;
		}
		unsigned char c = ((hi&0x0F)<<4) | (low&0x0F);
		*(p++) = c;
		offset++;
	}

	return offset;
}

char *RSA_convertIntToStr(int num,char *str,unsigned radix)
{
	/*索引表*/
	char index[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	unsigned unum;
	int i = 0,j,k;

	if((radix == 10) && (num < 0))
    {
        unum = num * (-1);
        str[i++]='-';
	}
	else
        unum = (unsigned)num;

	do
	{
        str[i++] = index[unum%(unsigned)radix];
        unum /= radix;
	}while(unum);
	str[i]='\0';

	if(str[0] == '-')
        k=1;
	else
        k=0;

	for(j = k;j < (i-1) / 2 + k;j++)
	{
        num = str[j];
        str[j] = str[i-j-1+k];
        str[i-j-1+k] = num;
	}
	return str;
}

int RSA_getValueDependOnSize(uint8_t *p, int size)
{
    int ret = -1;

    switch (size)
    {
        case 1:
            ret = p[0] & 0x000000FF;
            break;
        case 2:
            ret = ((p[0] << 8 ) | p[1]) & 0x0000FFFF;
            break;
        case 3:
            ret = ((p[0] << 16 ) | (p[1] << 8) | p[2]) & 0x00FFFFFF;
            break;
        case 4:
            ret = ((p[0] << 24 ) | (p[1] << 16) | (p[2] << 8) | p[3]) & 0xFFFFFFFF;
            break;
        default:
            break;
    }

    return ret;
}

void RSA_fillStr(char* dest, char* src, int totalLen, char content, char sig)
{
    int srcLen = (int)strlen(src);
    if (srcLen < totalLen)
    {
        switch (sig)
        {
        case 'L':
            {
                int j = 0;
                for (int i = 0; i < totalLen; i++)
                {
                    if( i < (totalLen - srcLen) )
                    {
                        dest[i] = content;
                    }
                    else
                    {
                        dest[i] = src[j];
                        j++;
                    }
                }
            }
            break;
        case 'R':
            {
                for (int i = 0; i < totalLen; i++)
                {
                    if(i < srcLen)
                    {
                        dest[i] = src[i];
                    }
                    else
                    {
                        dest[i] = content;
                    }
                }
            }
            break;
        default:
            break;
        }
    }
    else
    {
        memcpy(dest, src, totalLen);
    }
}

int RSA_getCompressedBCDArray(uint8_t *dest, uint8_t *src, int srcLen)
{
    int destLen = srcLen/2;
    if(srcLen % 2 != 0)
    {
        destLen++;
    }

    for(int i = 0; i < destLen; i++)
    {
        dest[i] = src[2 * i] << 4 | src[2 * i + 1];
    }

    return destLen / 2;
}
