/*
	NN.H - header file for NN.C

    Copyright (c) J.S.A.Kapp 1994 - 1996.

	RSAEURO - RSA Library compatible with RSAREF 2.0.

	All functions prototypes are the Same as for RSAREF.
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF uses.  This should aid
				direct importing to your applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	Math Library Routines Header File.

	Revision 1.00 - JSAK.
*/

#ifndef _RSA_XNN_H_
#define _RSA_XNN_H_

#ifdef __cplusplus
extern "C" {
#endif


#ifndef PROTOTYPES
#define PROTOTYPES 1
#endif

/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;

/* UINT2 defines a two byte word */
typedef unsigned short int UINT2;

/* UINT4 defines a four byte word */
typedef unsigned long int UINT4;

/* BYTE defines a unsigned character */
typedef unsigned char BYTE;

/* internal signed value */
typedef signed long int signeddigit;

#ifndef NULL_PTR
#define NULL_PTR ((POINTER)0)
#endif

#ifndef UNUSED_ARG
#define UNUSED_ARG(x) x = *(&x);
#endif


/* Type definitions. */

typedef UINT4 XNN_DIGIT;
typedef UINT2 XNN_HALF_DIGIT;


/* Length of digit in bits */
#define XNN_DIGIT_BITS 32
#define XNN_HALF_DIGIT_BITS 16
/* Length of digit in bytes */
#define XNN_DIGIT_LEN (XNN_DIGIT_BITS / 8)
/* Maximum length in digits */
#define MAX_XNN_Digits \
  ((MAX_RSA_MODULUS_LEN + XNN_DIGIT_LEN - 1) / XNN_DIGIT_LEN + 1)
/* Maximum digits */
#define MAX_XNN_DIGIT 0xffffffff
#define MAX_XNN_HALF_DIGIT 0xffff

#define XNN_LT   -1
#define XNN_EQ   0
#define XNN_GT 1

/* Macros. */

#define LOW_HALF(x) ((x) & MAX_XNN_HALF_DIGIT)
#define HIGH_HALF(x) (((x) >> XNN_HALF_DIGIT_BITS) & MAX_XNN_HALF_DIGIT)
#define TO_HIGH_HALF(x) (((XNN_DIGIT)(x)) << XNN_HALF_DIGIT_BITS)
#define DIGIT_MSB(x) (unsigned int)(((x) >> (XNN_DIGIT_BITS - 1)) & 1)
#define DIGIT_2MSB(x) (unsigned int)(((x) >> (XNN_DIGIT_BITS - 2)) & 3)

void XNN_Decode(XNN_DIGIT *, unsigned int, unsigned char *, unsigned int);
void XNN_Encode(unsigned char *, unsigned int, XNN_DIGIT *, unsigned int);

void XNN_Assign(XNN_DIGIT *, XNN_DIGIT *, unsigned int);
void XNN_AssignZero(XNN_DIGIT *, unsigned int);
void XNN_Assign2Exp(XNN_DIGIT *, unsigned int, unsigned int);

XNN_DIGIT XNN_Add(XNN_DIGIT *, XNN_DIGIT *, XNN_DIGIT *, unsigned int);
XNN_DIGIT XNN_Sub(XNN_DIGIT *, XNN_DIGIT *, XNN_DIGIT *, unsigned int);
void XNN_Mult(XNN_DIGIT *, XNN_DIGIT *, XNN_DIGIT *, unsigned int);
void XNN_Div(XNN_DIGIT *, XNN_DIGIT *, XNN_DIGIT *, unsigned int, XNN_DIGIT *,unsigned int);
XNN_DIGIT XNN_LShift(XNN_DIGIT *, XNN_DIGIT *, unsigned int, unsigned int);
XNN_DIGIT XNN_RShift(XNN_DIGIT *, XNN_DIGIT *, unsigned int, unsigned int);
XNN_DIGIT XNN_LRotate(XNN_DIGIT *, XNN_DIGIT *, unsigned int, unsigned int);

void XNN_Mod(XNN_DIGIT *, XNN_DIGIT *, unsigned int, XNN_DIGIT *, unsigned int);
void XNN_ModMult(XNN_DIGIT *, XNN_DIGIT *, XNN_DIGIT *, XNN_DIGIT *, unsigned int);
void XNN_ModExp(XNN_DIGIT *, XNN_DIGIT *, XNN_DIGIT *, unsigned int, XNN_DIGIT *,unsigned int);
void XNN_ModInv(XNN_DIGIT *, XNN_DIGIT *, XNN_DIGIT *, unsigned int);
void XNN_Gcd(XNN_DIGIT *, XNN_DIGIT *, XNN_DIGIT *, unsigned int);

int XNN_Cmp(XNN_DIGIT *, XNN_DIGIT *, unsigned int);
int XNN_Zero(XNN_DIGIT *, unsigned int);
unsigned int XNN_Bits(XNN_DIGIT *, unsigned int);
unsigned int XNN_Digits(XNN_DIGIT *, unsigned int);

int XNN_BigintstrToHexBytes(unsigned char *biginteger,unsigned char *outHexBytes);

#define XNN_Assign_DIGIT(a, b, digits) {XNN_AssignZero (a, digits); a[0] = b;}
#define XNN_EQUAL(a, b, digits) (! XNN_Cmp (a, b, digits))
#define XNN_EVEN(a, digits) (((digits) == 0) || ! (a[0] & 1))
#define XNN_CHARTOINT(a) (a-0x30)
#define XNN_INTTOCHAR(a) (a+0x30)


#define MIN_RSA_MODULUS_BITS 508
/*
	 PGP 2.6.2 Now allows 2048-bit keys changing below will allow this.
     It does lengthen key generation slightly if the value is increased.
*/
#define MAX_RSA_MODULUS_BITS (1024*3)
#define MAX_RSA_MODULUS_LEN ((MAX_RSA_MODULUS_BITS + 7) / 8)
#define MAX_RSA_PRIME_BITS ((MAX_RSA_MODULUS_BITS + 1) / 2)
#define MAX_RSA_PRIME_LEN ((MAX_RSA_PRIME_BITS + 7) / 8)

/* Maximum lengths of encoded and encrypted content, as a function of
	 content length len. Also, inverse functions. */

#define ENCODED_CONTENT_LEN(len) (4*(len)/3 + 3)
#define ENCRYPTED_CONTENT_LEN(len) ENCODED_CONTENT_LEN ((len)+8)
#define DECODED_CONTENT_LEN(len) (3*(len)/4 + 1)
#define DECRYPTED_CONTENT_LEN(len) (DECODED_CONTENT_LEN (len) - 1)

/* Maximum lengths of signatures, encrypted keys, encrypted
	 signatures, and message digests. */

#define MAX_SIGNATURE_LEN MAX_RSA_MODULUS_LEN
#define MAX_PEM_SIGNATURE_LEN ENCODED_CONTENT_LEN(MAX_SIGNATURE_LEN)
#define MAX_ENCRYPTED_KEY_LEN MAX_RSA_MODULUS_LEN
#define MAX_PEM_ENCRYPTED_KEY_LEN ENCODED_CONTENT_LEN(MAX_ENCRYPTED_KEY_LEN)
#define MAX_PEM_ENCRYPTED_SIGNATURE_LEN ENCRYPTED_CONTENT_LEN(MAX_SIGNATURE_LEN)
#define MAX_DIGEST_LEN 20

/* Maximum length of Diffie-Hellman parameters. */

#define DH_PRIME_LEN(bits) (((bits) + 7) / 8)

/* Error codes. */

#define RE_CONTENT_ENCODING 0x0400
#define RE_DATA 0x0401
#define RE_DIGEST_ALGORITHM 0x0402
#define RE_ENCODING 0x0403
#define RE_KEY 0x0404
#define RE_KEY_ENCODING 0x0405
#define RE_LEN 0x0406
#define RE_MODULUS_LEN 0x0407
#define RE_NEED_RANDOM 0x0408
#define RE_PRIVATE_KEY 0x0409
#define RE_PUBLIC_KEY 0x040a
#define RE_SIGNATURE 0x040b
#define RE_SIGNATURE_ENCODING 0x040c
#define RE_ENCRYPTION_ALGORITHM 0x040d
#define RE_FILE 0x040e

/* Library details. */

#define RSAEURO_VER_MAJ 1
#define RSAEURO_VER_MIN 04
#define RSAEURO_IDENT "RSAEURO Toolkit"
#define RSAEURO_DATE "21/08/94"

/* Internal Error Codes */

/* IDOK and IDERROR changed to ID_OK and ID_ERROR */

#define ID_OK    0
#define ID_ERROR 1

/* Internal defs. */

#define TRUE    1
#define FALSE   0

/* RSAEuro Info Structure */

typedef struct {
    unsigned short int Version;                 /* RSAEuro Version */
    unsigned int flags;                         /* Version Flags */
    unsigned char ManufacturerID[32];           /* Toolkit ID */
    unsigned int Algorithms;                    /* Algorithms Supported */
} RSAEUROINFO;

/* Random structure. */

typedef struct {
  unsigned int bytesNeeded;                    /* seed bytes required */
  unsigned char state[16];                     /* state of object */
  unsigned int outputAvailable;                /* number byte available */
  unsigned char output[16];                    /* output bytes */
} R_RANDOM_STRUCT;

/* RSA public and private key. */

typedef struct {
  unsigned short int bits;                     /* length in bits of modulus */
  unsigned char modulus[MAX_RSA_MODULUS_LEN];  /* modulus */
  unsigned char exponent[MAX_RSA_MODULUS_LEN]; /* public exponent */
} R_RSA_PUBLIC_KEY;

typedef struct {
  unsigned short int bits;                     /* length in bits of modulus */
  unsigned char modulus[MAX_RSA_MODULUS_LEN];  /* modulus */
  unsigned char publicExponent[MAX_RSA_MODULUS_LEN];     /* public exponent */
  unsigned char exponent[MAX_RSA_MODULUS_LEN]; /* private exponent */
  unsigned char prime[2][MAX_RSA_PRIME_LEN];   /* prime factors */
  unsigned char primeExponent[2][MAX_RSA_PRIME_LEN];     /* exponents for CRT */
  unsigned char coefficient[MAX_RSA_PRIME_LEN];          /* CRT coefficient */
} R_RSA_PRIVATE_KEY;

/* RSA prototype key. */


void XR_memset(unsigned char *, unsigned char, unsigned int);
void XR_memcpy(unsigned char *, unsigned char *, unsigned int);
int XR_memcmp(unsigned char *, unsigned char *, unsigned int);

#ifdef __cplusplus
}
#endif

#endif /* _XNN_H_ */
