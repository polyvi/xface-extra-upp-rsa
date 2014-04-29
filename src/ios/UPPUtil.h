//
//  UPPUtil.h
//  xFace
//
//  Created by hejp raul on 12-5-23.
//  Copyright (c) 2012年 Polyvi Inc. All rights reserved.
//

#ifndef xFace_UPPUtil_h
#define xFace_UPPUtil_h

/**
 HEX编码 将数组转换成16进制字符串.
 如0x12 0x2A 0x01 转换为"122A01"
 @param data    被编码的数据
 @param len     被编码数据长度
 @param des     编码后的数据
 @returns void
 */
void RSA_hexEncode(char* data, int len, char* des);

/**
 HEX解码 将成16进制字符串转换成数组.
 如"122A01"转换为0x12 0x2A 0x01
 @param data    被解码的数据
 @param len     被解码数据长度
 @param des     解码后的数据
 @returns 成功返回解码后长度，否则返回(-1)
 */
int RSA_hexDecode(char* data, int len, char* des);

/**
 整型数转换成对应进制数的字符串
 @param num     需要转换的整形数
 @param str     转换后的字符串
 @param radix   转换的进制数
 @returns   成功返回转换后的字符串，失败返回NULL
 */
char *RSA_convertIntToStr(int num,char *str,unsigned radix);

/**
 根据长度、地址获取小端模式值
 @param p   取值区域首地址
 @param size取值区域大小
 @return    成功返回取到的值，否则返回-1
 */
int RSA_getValueDependOnSize(uint8_t *p, int size);

/**
 填充字符串，如果源字符串不足长度用参数指定字符补齐
 @param dest    目标字符串
 @param src     源字符串
 @param totalLen对齐长度
 @param content 指定补齐时用的字符
 @param sig     补齐方式，‘L’表示左对齐，‘R’表示右对齐
 */
void RSA_fillStr(char* dest, char* src, int totalLen, char content, char sig);

/**
 非压缩字节转换为压缩BCD码
 @param dest    转换后输出的压缩BCD码
 @param src     需要转换的字节数组
 @param srcLen  字节数组长度
 @return    转换后压缩BCD码的长度
 */
int RSA_getCompressedBCDArray(uint8_t *dest, uint8_t *src, int srcLen);

#endif
