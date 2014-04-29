/*
	RSA.H - header file for RSA.C

    Copyright (c) J.S.A.Kapp 1994 - 1996.

	RSAEURO - RSA Library compatible with RSAREF 2.0.

	All functions prototypes are the Same as for RSAREF.
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF uses.  This should aid
        direct importing to your applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	RSA Routines Header File.

	Revision 1.00 - JSAK.
*/
/* RSA key lengths. */
#ifndef _RSA_H_
#define _RSA_H_

#include "Rsa_nn.h"

int XRSAPublicEncrypt(unsigned char *, unsigned int *, unsigned char *, unsigned int,R_RSA_PUBLIC_KEY *);
int XRSAPrivateEncrypt(unsigned char *, unsigned int *, unsigned char *, unsigned int,R_RSA_PRIVATE_KEY *);
int XRSAPublicDecrypt(unsigned char *, unsigned int *, unsigned char *, unsigned int, R_RSA_PUBLIC_KEY *);
int XRSAPrivateDecrypt(unsigned char *, unsigned int *, unsigned char *, unsigned int,R_RSA_PRIVATE_KEY *);
/************************************************************************
* 公钥加密
*
*@param modulus 公钥模数
*@param exmod	公钥指数
*@param pin		要加密的明文数据
*@param le		明文数据的长度
*@param pout	加密后代密文数据
*@param poutlen 密文数据的长度
*return 0	成功，其他 －失败
*
************************************************************************/
int XRSA_PublicEncrypt(const char *modulus,const char *exmod,const const char *pin,unsigned int le,
					  char *pout,unsigned int *poutlen);

/************************************************************************
* 公钥解密
*
*@param modulus 公钥模数
*@param exmod	公钥指数
*@param pin		要解密的密文数据
*@param le		密文数据长度
*@param pout	解密后的明文数据
*@param poutlen 解密后明文数据长度
*return 0	成功，其他 －失败
*
************************************************************************/
int XRSA_PublicDecrypt(const char *modulus,const char *exmod,const char *pin,unsigned int le,
					   char *pout,unsigned int *poutlen);

#endif




