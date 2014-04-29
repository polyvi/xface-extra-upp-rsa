/*
	RSA.C - RSA routines for RSAEURO

    Copyright (c) J.S.A.Kapp 1994 - 1996.

	RSAEURO - RSA Library compatible with RSAREF(tm) 2.0.

	All functions prototypes are the Same as for RSAREF(tm).
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF(tm) uses.  This should aid
	direct importing to your applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	All Trademarks Acknowledged.

	RSA encryption performed as defined in the PKCS (#1) by RSADSI.

	Revision history
		0.90 First revision, code produced very similar to that
		of RSAREF(tm), still it worked fine.

        0.91 Second revision, code altered to aid speeding up.
		Used pointer accesses to arrays to speed up some parts,
		mainly during the loops.

        1.03 Third revision, Random Structure initialization
        double check, RSAPublicEncrypt can now return RE_NEED_RANDOM.
*/


#include "Rsa.h"
#include <stdlib.h>


/* Secure memcpy routine */

void XR_memcpy(unsigned char * output,unsigned char * input,unsigned int len)
{
	if (len != 0) {
		do {
			*output++ = *input++;
		}while (--len != 0);
	}
}

/* Secure memcmp routine */

int XR_memcmp(unsigned char * Block1,unsigned char * Block2,unsigned int len)
{
	if(len != 0) {
		/* little trick in declaring vars */
		register const unsigned char *p1 = Block1, *p2 = Block2;

		do {
			if(*p1++ != *p2++)
				return(*--p1 - *--p2);
		}while(--len != 0);
	}
	return(0);
}

void XR_memset(unsigned char *output,unsigned char data,unsigned int len)
{
	if(len != 0) {
		do {
			*output++ = (unsigned char)data;
		}while(--len != 0);
	}
}

static int rsapublicfunc(unsigned char *, unsigned int *, unsigned char *, unsigned int, R_RSA_PUBLIC_KEY *);
static int rsaprivatefunc(unsigned char *, unsigned int *, unsigned char *, unsigned int, R_RSA_PRIVATE_KEY *);

/* RSA encryption, according to RSADSI's PKCS #1. */

int XRSAPublicEncrypt(unsigned char *output, unsigned int *outputLen, unsigned char *input,
						unsigned int inputLen, R_RSA_PUBLIC_KEY *publicKey)
{
	int status;
	unsigned char byte, pkcsBlock[MAX_RSA_MODULUS_LEN];
	unsigned int i, modulusLen;
	int random;

	modulusLen = (publicKey->bits + 7) / 8;

	if(inputLen + 11 > modulusLen)
        return(RE_LEN);

	*pkcsBlock = 0;                 /* PKCS Block Makeup */

		/* block type 2 */
	*(pkcsBlock+1) = 2;

	for(i = 2; i < modulusLen - inputLen - 1; i++) {
		random = rand();

		if((random&0xFF)==0)
			random|=0x0F;

		*(pkcsBlock+i) = (char)random;
	}

	/* separator */
	pkcsBlock[i++] = 0;

	XR_memcpy((POINTER)&pkcsBlock[i], (POINTER)input, inputLen);

	status = rsapublicfunc(output, outputLen, pkcsBlock, modulusLen, publicKey);

	/* Clear sensitive information. */

	byte = 0;
	XR_memset((POINTER)pkcsBlock, 0, sizeof(pkcsBlock));

	return(status);
}

/* RSA decryption, according to RSADSI's PKCS #1. */

int XRSAPublicDecrypt(unsigned char *output,unsigned int *outputLen, unsigned char *input,
						unsigned int inputLen,R_RSA_PUBLIC_KEY *publicKey)
{
	int status;
	unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];
	unsigned int i, modulusLen, pkcsBlockLen;

	modulusLen = (publicKey->bits + 7) / 8;

	if(inputLen > modulusLen)
		return(RE_LEN);

	status = rsapublicfunc(pkcsBlock, &pkcsBlockLen, input, inputLen, publicKey);
	if(status)
		return(status);

	if(pkcsBlockLen != modulusLen)
		return(RE_LEN);

	/* Require block type 1. */

	if((pkcsBlock[0] != 0) || (pkcsBlock[1] != 1))
	 return(RE_DATA);

	for(i = 2; i < modulusLen-1; i++)
		if(*(pkcsBlock+i) != 0xff)
			break;

	/* separator check */

	if(pkcsBlock[i++] != 0)
		return(RE_DATA);

	*outputLen = modulusLen - i;

	if(*outputLen + 11 > modulusLen)
		return(RE_DATA);

	XR_memcpy((POINTER)output, (POINTER)&pkcsBlock[i], *outputLen);

	/* Clear sensitive information. */

	XR_memset((POINTER)pkcsBlock, 0, sizeof(pkcsBlock));

	return(ID_OK);
}

/* RSA encryption, according to RSADSI's PKCS #1. */

int XRSAPrivateEncrypt(unsigned char *output, unsigned int *outputLen, unsigned char *input,
					  unsigned int inputLen, R_RSA_PRIVATE_KEY *privateKey)
{
	int status;
	unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];
	unsigned int i, modulusLen;

	modulusLen = (privateKey->bits + 7) / 8;

	if(inputLen + 11 > modulusLen)
		return (RE_LEN);

	*pkcsBlock = 0;
	/* block type 1 */
	*(pkcsBlock+1) = 1;

	for (i = 2; i < modulusLen - inputLen - 1; i++)
		*(pkcsBlock+i) = 0xff;

	/* separator */
	pkcsBlock[i++] = 0;

	XR_memcpy((POINTER)&pkcsBlock[i], (POINTER)input, inputLen);

	status = rsaprivatefunc(output, outputLen, pkcsBlock, modulusLen, privateKey);

	/* Clear sensitive information. */

	XR_memset((POINTER)pkcsBlock, 0, sizeof(pkcsBlock));

	return(status);
}

/* RSA decryption, according to RSADSI's PKCS #1. */

int XRSAPrivateDecrypt(unsigned char *output, unsigned int *outputLen,unsigned char *input,
					  unsigned int inputLen, R_RSA_PRIVATE_KEY *privateKey)
{
	int status;
	unsigned char pkcsBlock[MAX_RSA_MODULUS_LEN];
	unsigned int i, modulusLen, pkcsBlockLen;

	modulusLen = (privateKey->bits + 7) / 8;

	if(inputLen > modulusLen)
		return (RE_LEN);

	status = rsaprivatefunc(pkcsBlock, &pkcsBlockLen, input, inputLen, privateKey);
	if(status)
		return (status);

	if(pkcsBlockLen != modulusLen)
		return (RE_LEN);

	/* We require block type 2. */

	if((*pkcsBlock != 0) || (*(pkcsBlock+1) != 2))
	 return (RE_DATA);

	for(i = 2; i < modulusLen-1; i++)
		/* separator */
		if (*(pkcsBlock+i) == 0)
			break;

	i++;
	if(i >= modulusLen)
		return(RE_DATA);

	*outputLen = modulusLen - i;

	if(*outputLen + 11 > modulusLen)
		return(RE_DATA);

	XR_memcpy((POINTER)output, (POINTER)&pkcsBlock[i], *outputLen);

	/* Clear sensitive information. */
	XR_memset((POINTER)pkcsBlock, 0, sizeof(pkcsBlock));

	return(ID_OK);
}

/* Raw RSA public-key operation. Output has same length as modulus.

	 Requires input < modulus.
*/
static int rsapublicfunc(unsigned char *output, unsigned int *outputLen,unsigned char *input,
						 unsigned int inputLen, R_RSA_PUBLIC_KEY *publicKey)
{
	XNN_DIGIT c[MAX_XNN_Digits], e[MAX_XNN_Digits], m[MAX_XNN_Digits],
		n[MAX_XNN_Digits];
	unsigned int eDigits, nDigits;


		/* decode the required RSA function input data */
	XNN_Decode(m, MAX_XNN_Digits, input, inputLen);
	XNN_Decode(n, MAX_XNN_Digits, publicKey->modulus, MAX_RSA_MODULUS_LEN);
	XNN_Decode(e, MAX_XNN_Digits, publicKey->exponent, MAX_RSA_MODULUS_LEN);

	nDigits = XNN_Digits(n, MAX_XNN_Digits);
	eDigits = XNN_Digits(e, MAX_XNN_Digits);

	if(XNN_Cmp(m, n, nDigits) >= 0)
		return(RE_DATA);

	*outputLen = (publicKey->bits + 7) / 8;

	/* Compute c = m^e mod n.  To perform actual RSA calc.*/

	XNN_ModExp (c, m, e, eDigits, n, nDigits);

	/* encode output to standard form */
	XNN_Encode (output, *outputLen, c, nDigits);

	/* Clear sensitive information. */

	XR_memset((POINTER)c, 0, sizeof(c));
	XR_memset((POINTER)m, 0, sizeof(m));

	return(ID_OK);
}

/* Raw RSA private-key operation. Output has same length as modulus.

	 Requires input < modulus.
*/

static int rsaprivatefunc(unsigned char *output, unsigned int *outputLen, unsigned char *input,
						  unsigned int inputLen,R_RSA_PRIVATE_KEY *privateKey)
{
	XNN_DIGIT c[MAX_XNN_Digits], cP[MAX_XNN_Digits], cQ[MAX_XNN_Digits],
		dP[MAX_XNN_Digits], dQ[MAX_XNN_Digits], mP[MAX_XNN_Digits],
		mQ[MAX_XNN_Digits], n[MAX_XNN_Digits], p[MAX_XNN_Digits], q[MAX_XNN_Digits],
		qInv[MAX_XNN_Digits], t[MAX_XNN_Digits];
	unsigned int cDigits, nDigits, pDigits;

	/* decode required input data from standard form */
	XNN_Decode(c, MAX_XNN_Digits, input, inputLen);           /* input */

					/* private key data */
	XNN_Decode(p, MAX_XNN_Digits, privateKey->prime[0], MAX_RSA_PRIME_LEN);
	XNN_Decode(q, MAX_XNN_Digits, privateKey->prime[1], MAX_RSA_PRIME_LEN);
	XNN_Decode(dP, MAX_XNN_Digits, privateKey->primeExponent[0], MAX_RSA_PRIME_LEN);
	XNN_Decode(dQ, MAX_XNN_Digits, privateKey->primeExponent[1], MAX_RSA_PRIME_LEN);
	XNN_Decode(n, MAX_XNN_Digits, privateKey->modulus, MAX_RSA_MODULUS_LEN);
	XNN_Decode(qInv, MAX_XNN_Digits, privateKey->coefficient, MAX_RSA_PRIME_LEN);
		/* work out lengths of input components */

    cDigits = XNN_Digits(c, MAX_XNN_Digits);
    pDigits = XNN_Digits(p, MAX_XNN_Digits);
	nDigits = XNN_Digits(n, MAX_XNN_Digits);


	if(XNN_Cmp(c, n, nDigits) >= 0)
		return(RE_DATA);

	*outputLen = (privateKey->bits + 7) / 8;

	/* Compute mP = cP^dP mod p  and  mQ = cQ^dQ mod q. (Assumes q has
		 length at most pDigits, i.e., p > q.)
	*/

	XNN_Mod(cP, c, cDigits, p, pDigits);
	XNN_Mod(cQ, c, cDigits, q, pDigits);

	XNN_AssignZero(mP, nDigits);
	XNN_ModExp(mP, cP, dP, pDigits, p, pDigits);

	XNN_AssignZero(mQ, nDigits);
	XNN_ModExp(mQ, cQ, dQ, pDigits, q, pDigits);

	/* Chinese Remainder Theorem:
			m = ((((mP - mQ) mod p) * qInv) mod p) * q + mQ.
	*/

	if(XNN_Cmp(mP, mQ, pDigits) >= 0) {
		XNN_Sub(t, mP, mQ, pDigits);
	}else{
		XNN_Sub(t, mQ, mP, pDigits);
		XNN_Sub(t, p, t, pDigits);
	}

	XNN_ModMult(t, t, qInv, p, pDigits);
	XNN_Mult(t, t, q, pDigits);
	XNN_Add(t, t, mQ, nDigits);

	/* encode output to standard form */
	XNN_Encode (output, *outputLen, t, nDigits);

	/* Clear sensitive information. */
	XR_memset((POINTER)c, 0, sizeof(c));
	XR_memset((POINTER)cP, 0, sizeof(cP));
	XR_memset((POINTER)cQ, 0, sizeof(cQ));
	XR_memset((POINTER)dP, 0, sizeof(dP));
	XR_memset((POINTER)dQ, 0, sizeof(dQ));
	XR_memset((POINTER)mP, 0, sizeof(mP));
	XR_memset((POINTER)mQ, 0, sizeof(mQ));
	XR_memset((POINTER)p, 0, sizeof(p));
	XR_memset((POINTER)q, 0, sizeof(q));
	XR_memset((POINTER)qInv, 0, sizeof(qInv));
	XR_memset((POINTER)t, 0, sizeof(t));
	return(ID_OK);
}

/************************************************************************
 * 公钥加密
 *
 *@param modulus 公钥模数
 *@param exmod	公钥指数
 *@param pin	要加密的明文数据
 *@param le		明文数据的长度
 *@param pout	加密后代密文数据
 *@param poutlen 密文数据的长度
 *return 0	成功，其他 －失败
 *
 ************************************************************************/
int XRSA_PublicEncrypt(const char *modulus,const char *exmod,const const char *pin,unsigned int le,
					  char *pout,unsigned int *poutlen)
{
	R_RSA_PUBLIC_KEY publicKey;
	unsigned char temp[1024]={0};
	int len;
	int i =0;
	int ret;

	XR_memset((unsigned char *)&publicKey,0x00,sizeof(R_RSA_PUBLIC_KEY));

	len = XNN_BigintstrToHexBytes((unsigned char *)modulus,temp);
	if(len>MAX_RSA_MODULUS_LEN)
		return 1;

	publicKey.bits = len*8;

	for(i= 0;i<len;i++){
		publicKey.modulus[MAX_RSA_MODULUS_LEN-len+i]= temp[i];
	}

	len = XNN_BigintstrToHexBytes((unsigned char *)exmod,temp);
	for(i= 0;i<len;i++){
		publicKey.exponent[MAX_RSA_MODULUS_LEN-len+i]= temp[i];
	}

	ret = XRSAPublicEncrypt(pout, poutlen, pin, le, &publicKey);

	return ret;
}

/************************************************************************
 * 公钥解密
 *
 *@param modulus 公钥模数
 *@param exmod	公钥指数
 *@param pin	要解密的密文数据
 *@param le		密文数据长度
 *@param pout	解密后的明文数据
 *@param poutlen 解密后明文数据长度
 *return 0	成功，其他 －失败
 *
 ************************************************************************/
int XRSA_PublicDecrypt(const char *modulus,const char *exmod,const char *pin,unsigned int le,
                      char *pout,unsigned int *poutlen)
{
	R_RSA_PUBLIC_KEY publicKey;
	unsigned char temp[1024]={0};
	int len;
	int i =0;
	int ret;

	XR_memset((unsigned char *)&publicKey,0x00,sizeof(R_RSA_PUBLIC_KEY));

	len = XNN_BigintstrToHexBytes((unsigned char *)modulus,temp);
	if(len>MAX_RSA_MODULUS_LEN)
		return 1;

	publicKey.bits = len*8;

	for(i= 0;i<len;i++){
		publicKey.modulus[MAX_RSA_MODULUS_LEN-len+i]= temp[i];
	}

	len = XNN_BigintstrToHexBytes((unsigned char *)exmod,temp);
	for(i= 0;i<len;i++){
		publicKey.exponent[MAX_RSA_MODULUS_LEN-len+i]= temp[i];
	}

	ret = XRSAPublicDecrypt(pout, poutlen, pin, le, &publicKey);

	return ret;
}
