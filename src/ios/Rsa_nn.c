/*
	NN.C - natural numbers routines

    Copyright (c) J.S.A.Kapp 1994 - 1996.

	RSAEURO - RSA Library compatible with RSAREF(tm) 2.0.

	All functions prototypes are the Same as for RSAREF(tm).
	To aid compatiblity the source and the files follow the
	same naming comventions that RSAREF(tm) uses.  This should aid
	direct importing to you applications.

	This library is legal everywhere outside the US.  And should
	NOT be imported to the US and used there.

	All Trademarks Acknowledged.

	Revision hisitory
		0.90 First revision, this revision was the basic routines.
		Routines slower than final revision.

		0.91 Second revision, this is the current revision, all
		routines have been altered for speed increases.  Also the
		addition of assembler equivalents.

        1.02 Third revision, minor bug fixes.
        dmult bug fix, Bug reported by Anders Heerfordt <i3683@dc.dk>.

        1.03 Fourth revision, SunCompiler patch

        1.04 Fifth revision, Fix to fix problem with XNN_Encode
        and XNN_Decode when running with MS Visual C++ 4.x.
*/


#include "Rsa_nn.h"
#include <string.h>

/* internal static functions */

static XNN_DIGIT subdigitmult(XNN_DIGIT *, XNN_DIGIT *, XNN_DIGIT, XNN_DIGIT *, unsigned int);

static void dmult(XNN_DIGIT, XNN_DIGIT, XNN_DIGIT *, XNN_DIGIT *);

static unsigned int XNN_DigitBits(XNN_DIGIT);

/* Decodes character string b into a, where character string is ordered
	 from most to least significant.

	 Lengths: a[digits], b[len].
	 Assumes b[i] = 0 for i < len - digits * XNN_DIGIT_LEN. (Otherwise most
	 significant bytes are truncated.)
 */

void XNN_Decode(XNN_DIGIT *a, unsigned int digits, unsigned char *b, unsigned int len)
{
  XNN_DIGIT t;
  unsigned int i, u;
  int j;

            /* @##$ unsigned/signed bug fix added JSAK - Fri  31/05/96 18:09:11 */
  for (i = 0, j = len - 1; i < digits && j >= 0; i++) {
    t = 0;
    for (u = 0; j >= 0 && u < XNN_DIGIT_BITS; j--, u += 8)
			t |= ((XNN_DIGIT)b[j]) << u;
		a[i] = t;
  }

  for (; i < digits; i++)
    a[i] = 0;
}
void XNN_Encode(unsigned char *a, unsigned int len, XNN_DIGIT *b, unsigned int digits)
{
	XNN_DIGIT t;
    unsigned int i, u;
    int j;

            /* @##$ unsigned/signed bug fix added JSAK - Fri  31/05/96 18:09:11 */
    for (i = 0, j = len - 1; i < digits && j >= 0; i++) {
		t = b[i];
        for (u = 0; j >= 0 && u < XNN_DIGIT_BITS; j--, u += 8)
			a[j] = (unsigned char)(t >> u);
	}

    for (; j >= 0; j--)
		a[j] = 0;
}

/* Assigns a = 0. */

void XNN_AssignZero(XNN_DIGIT *a,unsigned int digits)
{
	if(digits) {
		do {
			*a++ = 0;
		}while(--digits);
	}
}


/* Assigns a = 2^b.

   Lengths: a[digits].
	 Requires b < digits * XNN_DIGIT_BITS.
 */
void XNN_Assign2Exp (XNN_DIGIT *a,unsigned int b,unsigned int digits)
{
  XNN_AssignZero (a, digits);

	if (b >= digits * XNN_DIGIT_BITS)
    return;

  a[b / XNN_DIGIT_BITS] = (XNN_DIGIT)1 << (b % XNN_DIGIT_BITS);
}

/* Computes a = b - c. Returns borrow.

	 Lengths: a[digits], b[digits], c[digits].
 */
XNN_DIGIT XNN_Sub (XNN_DIGIT *a, XNN_DIGIT *b, XNN_DIGIT *c, unsigned int digits)
{
	XNN_DIGIT temp, borrow = 0;

	if(digits)
		do {
            /* Bug fix 16/10/95 - JSK, code below removed, caused bug with
               Sun Compiler SC4.

			if((temp = (*b++) - borrow) == MAX_XNN_DIGIT)
                temp = MAX_XNN_DIGIT - *c++;
            */

            temp = *b - borrow;
            b++;
            if(temp == MAX_XNN_DIGIT) {
                temp = MAX_XNN_DIGIT - *c;
                c++;
            }else {      /* Patch to prevent bug for Sun CC */
                if((temp -= *c) > (MAX_XNN_DIGIT - *c))
					borrow = 1;
				else
					borrow = 0;
                c++;
            }
			*a++ = temp;
		}while(--digits);

	return(borrow);
}

/* Computes a = b * c.

	 Lengths: a[2*digits], b[digits], c[digits].
	 Assumes digits < MAX_XNN_Digits.
*/

void XNN_Mult (XNN_DIGIT *a, XNN_DIGIT *b, XNN_DIGIT *c,unsigned int digits)
{
	XNN_DIGIT t[2*MAX_XNN_Digits];
	XNN_DIGIT dhigh, dlow, carry;
	unsigned int bDigits, cDigits, i, j;

	XNN_AssignZero (t, 2 * digits);

	bDigits = XNN_Digits (b, digits);
	cDigits = XNN_Digits (c, digits);

	for (i = 0; i < bDigits; i++) {
		carry = 0;
		if(*(b+i) != 0) {
			for(j = 0; j < cDigits; j++) {
				dmult(*(b+i), *(c+j), &dhigh, &dlow);
				if((*(t+(i+j)) = *(t+(i+j)) + carry) < carry)
					carry = 1;
				else
					carry = 0;
				if((*(t+(i+j)) += dlow) < dlow)
					carry++;
				carry += dhigh;
			}
		}
		*(t+(i+cDigits)) += carry;
	}


	XNN_Assign(a, t, 2 * digits);
}

/* Computes a = b * 2^c (i.e., shifts left c bits), returning carry.

	 Requires c < XNN_DIGIT_BITS. */

XNN_DIGIT XNN_LShift (XNN_DIGIT *a,XNN_DIGIT *b,unsigned int c,unsigned int digits)
{
	XNN_DIGIT temp, carry = 0;
	unsigned int t;

	if(c < XNN_DIGIT_BITS)
		if(digits) {

			t = XNN_DIGIT_BITS - c;

			do {
				temp = *b++;
				*a++ = (temp << c) | carry;
				carry = c ? (temp >> t) : 0;
			}while(--digits);
		}

	return (carry);
}

/* Computes a = c div 2^c (i.e., shifts right c bits), returning carry.

	 Requires: c < XNN_DIGIT_BITS. */

XNN_DIGIT XNN_RShift (XNN_DIGIT *a, XNN_DIGIT *b, unsigned int c,unsigned int digits)
{
	XNN_DIGIT temp, carry = 0;
	unsigned int t;

	if(c < XNN_DIGIT_BITS)
		if(digits) {

			t = XNN_DIGIT_BITS - c;

			do {
				digits--;
				temp = *(b+digits);
				*(a+digits) = (temp >> c) | carry;
				carry = c ? (temp << t) : 0;
			}while(digits);
		}

	return (carry);
}

/* Computes a = c div d and b = c mod d.

	 Lengths: a[cDigits], b[dDigits], c[cDigits], d[dDigits].
	 Assumes d > 0, cDigits < 2 * MAX_XNN_Digits,
					 dDigits < MAX_XNN_Digits.
*/

void XNN_Div (XNN_DIGIT *a, XNN_DIGIT *b, XNN_DIGIT *c,unsigned int cDigits, XNN_DIGIT *d,unsigned int dDigits)
{
	XNN_DIGIT ai, cc[2*MAX_XNN_Digits+1], dd[MAX_XNN_Digits], s;
	XNN_DIGIT t[2], u, v, *ccptr;
	XNN_HALF_DIGIT aHigh, aLow, cHigh, cLow;
	int i;
	unsigned int ddDigits, shift;

	ddDigits = XNN_Digits (d, dDigits);
	if(ddDigits == 0)
		return;

	shift = XNN_DIGIT_BITS - XNN_DigitBits (d[ddDigits-1]);
	XNN_AssignZero (cc, ddDigits);
	cc[cDigits] = XNN_LShift (cc, c, shift, cDigits);
	XNN_LShift (dd, d, shift, ddDigits);
	s = dd[ddDigits-1];

	XNN_AssignZero (a, cDigits);

	for (i = cDigits-ddDigits; i >= 0; i--) {
		if (s == MAX_XNN_DIGIT)
			ai = cc[i+ddDigits];
		else {
			ccptr = &cc[i+ddDigits-1];

			s++;
			cHigh = (XNN_HALF_DIGIT)HIGH_HALF (s);
			cLow = (XNN_HALF_DIGIT)LOW_HALF (s);

			*t = *ccptr;
			*(t+1) = *(ccptr+1);

			if (cHigh == MAX_XNN_HALF_DIGIT)
				aHigh = (XNN_HALF_DIGIT)HIGH_HALF (*(t+1));
			else
				aHigh = (XNN_HALF_DIGIT)(*(t+1) / (cHigh + 1));
			u = (XNN_DIGIT)aHigh * (XNN_DIGIT)cLow;
			v = (XNN_DIGIT)aHigh * (XNN_DIGIT)cHigh;
			if ((*t -= TO_HIGH_HALF (u)) > (MAX_XNN_DIGIT - TO_HIGH_HALF (u)))
				t[1]--;
			*(t+1) -= HIGH_HALF (u);
			*(t+1) -= v;

			while ((*(t+1) > cHigh) ||
						 ((*(t+1) == cHigh) && (*t >= TO_HIGH_HALF (cLow)))) {
				if ((*t -= TO_HIGH_HALF (cLow)) > MAX_XNN_DIGIT - TO_HIGH_HALF (cLow))
					t[1]--;
				*(t+1) -= cHigh;
				aHigh++;
			}

			if (cHigh == MAX_XNN_HALF_DIGIT)
				aLow = (XNN_HALF_DIGIT)LOW_HALF (*(t+1));
			else
				aLow =
			(XNN_HALF_DIGIT)((TO_HIGH_HALF (*(t+1)) + HIGH_HALF (*t)) / (cHigh + 1));
			u = (XNN_DIGIT)aLow * (XNN_DIGIT)cLow;
			v = (XNN_DIGIT)aLow * (XNN_DIGIT)cHigh;
			if ((*t -= u) > (MAX_XNN_DIGIT - u))
				t[1]--;
			if ((*t -= TO_HIGH_HALF (v)) > (MAX_XNN_DIGIT - TO_HIGH_HALF (v)))
				t[1]--;
			*(t+1) -= HIGH_HALF (v);

			while ((*(t+1) > 0) || ((*(t+1) == 0) && *t >= s)) {
				if ((*t -= s) > (MAX_XNN_DIGIT - s))
					t[1]--;
				aLow++;
			}

			ai = TO_HIGH_HALF (aHigh) + aLow;
			s--;
		}

		cc[i+ddDigits] -= subdigitmult(&cc[i], &cc[i], ai, dd, ddDigits);

		while (cc[i+ddDigits] || (XNN_Cmp (&cc[i], dd, ddDigits) >= 0)) {
			ai++;
			cc[i+ddDigits] -= XNN_Sub (&cc[i], &cc[i], dd, ddDigits);
		}

		a[i] = ai;
	}

	XNN_AssignZero (b, dDigits);
	XNN_RShift (b, cc, shift, ddDigits);
}


/* Computes a = b mod c.

	 Lengths: a[cDigits], b[bDigits], c[cDigits].
	 Assumes c > 0, bDigits < 2 * MAX_XNN_Digits, cDigits < MAX_XNN_Digits.
*/
void XNN_Mod (XNN_DIGIT *a, XNN_DIGIT *b, unsigned int bDigits, XNN_DIGIT *c, unsigned int cDigits)
{
    XNN_DIGIT t[2 * MAX_XNN_Digits];

	XNN_Div (t, a, b, bDigits, c, cDigits);
}

/* Computes a = b * c mod d.

   Lengths: a[digits], b[digits], c[digits], d[digits].
   Assumes d > 0, digits < MAX_XNN_Digits.
 */
void XNN_ModMult (XNN_DIGIT *a, XNN_DIGIT *b, XNN_DIGIT *c, XNN_DIGIT *d,unsigned int digits)
{
    XNN_DIGIT t[2*MAX_XNN_Digits];

	XNN_Mult (t, b, c, digits);
    XNN_Mod (a, t, 2 * digits, d, digits);
}

/* Computes a = b^c mod d.

   Lengths: a[dDigits], b[dDigits], c[cDigits], d[dDigits].
	 Assumes d > 0, cDigits > 0, dDigits < MAX_XNN_Digits.
 */
void XNN_ModExp (XNN_DIGIT *a, XNN_DIGIT *b, XNN_DIGIT *c,unsigned int cDigits, XNN_DIGIT *d,unsigned int dDigits)
{
    XNN_DIGIT bPower[3][MAX_XNN_Digits], ci, t[MAX_XNN_Digits];
    int i;
	unsigned int ciBits, j, s;

	/* Store b, b^2 mod d, and b^3 mod d.
	 */
	XNN_Assign (bPower[0], b, dDigits);
	XNN_ModMult (bPower[1], bPower[0], b, d, dDigits);
    XNN_ModMult (bPower[2], bPower[1], b, d, dDigits);

    XNN_Assign_DIGIT (t, 1, dDigits);

	cDigits = XNN_Digits (c, cDigits);
    for (i = cDigits - 1; i >= 0; i--) {
		ci = c[i];
		ciBits = XNN_DIGIT_BITS;

		/* Scan past leading zero bits of most significant digit.
		 */
		if (i == (int)(cDigits - 1)) {
			while (! DIGIT_2MSB (ci)) {
				ci <<= 2;
				ciBits -= 2;
			}
        }

        for (j = 0; j < ciBits; j += 2, ci <<= 2) {
        /* Compute t = t^4 * b^s mod d, where s = two MSB's of ci. */
            XNN_ModMult (t, t, t, d, dDigits);
            XNN_ModMult (t, t, t, d, dDigits);
            if ((s = DIGIT_2MSB (ci)) != 0)
            XNN_ModMult (t, t, bPower[s-1], d, dDigits);
        }
    }

	XNN_Assign (a, t, dDigits);
}

/* Compute a = 1/b mod c, assuming inverse exists.

   Lengths: a[digits], b[digits], c[digits].
	 Assumes gcd (b, c) = 1, digits < MAX_XNN_Digits.
 */
void XNN_ModInv (XNN_DIGIT *a, XNN_DIGIT *b, XNN_DIGIT *c,unsigned int digits)
{
    XNN_DIGIT q[MAX_XNN_Digits], t1[MAX_XNN_Digits], t3[MAX_XNN_Digits],
		u1[MAX_XNN_Digits], u3[MAX_XNN_Digits], v1[MAX_XNN_Digits],
		v3[MAX_XNN_Digits], w[2*MAX_XNN_Digits];
    int u1Sign;

    /* Apply extended Euclidean algorithm, modified to avoid negative
       numbers.
    */
    XNN_Assign_DIGIT (u1, 1, digits);
	XNN_AssignZero (v1, digits);
    XNN_Assign (u3, b, digits);
	XNN_Assign (v3, c, digits);
    u1Sign = 1;

	while (! XNN_Zero (v3, digits)) {
        XNN_Div (q, t3, u3, digits, v3, digits);
        XNN_Mult (w, q, v1, digits);
		XNN_Add (t1, u1, w, digits);
        XNN_Assign (u1, v1, digits);
		XNN_Assign (v1, t1, digits);
		XNN_Assign (u3, v3, digits);
		XNN_Assign (v3, t3, digits);
		u1Sign = -u1Sign;
	}

    /* Negate result if sign is negative. */
	if (u1Sign < 0)
		XNN_Sub (a, c, u1, digits);
	else
		XNN_Assign (a, u1, digits);
}

/* Computes a = gcd(b, c).

	 Assumes b > c, digits < MAX_XNN_Digits.
*/

#define iplus1  ( i==2 ? 0 : i+1 )      /* used by Euclid algorithms */
#define iminus1 ( i==0 ? 2 : i-1 )      /* used by Euclid algorithms */
#define g(i) (  &(t[i][0])  )

void XNN_Gcd(XNN_DIGIT *a ,XNN_DIGIT *b ,XNN_DIGIT *c, unsigned int digits)
{
	short i;
	XNN_DIGIT t[3][MAX_XNN_Digits];

	XNN_Assign(g(0), c, digits);
	XNN_Assign(g(1), b, digits);

	i=1;

	while(!XNN_Zero(g(i),digits)) {
		XNN_Mod(g(iplus1), g(iminus1), digits, g(i), digits);
		i = iplus1;
	}

	XNN_Assign(a , g(iminus1), digits);
}

/* Returns the significant length of a in bits.

	 Lengths: a[digits]. */

unsigned int XNN_Bits (XNN_DIGIT *a,unsigned int digits)
{
	if ((digits = XNN_Digits (a, digits)) == 0)
		return (0);

	return ((digits - 1) * XNN_DIGIT_BITS + XNN_DigitBits (a[digits-1]));
}

#ifndef USEASM

/* Returns sign of a - b. */

int XNN_Cmp (XNN_DIGIT *a, XNN_DIGIT *b, unsigned int digits)
{

	if(digits) {
		do {
			digits--;
			if(*(a+digits) > *(b+digits))
				return(1);
			if(*(a+digits) < *(b+digits))
				return(-1);
		}while(digits);
	}

	return (0);
}

/* Returns nonzero iff a is zero. */

int XNN_Zero (XNN_DIGIT *a,unsigned int digits)
{
	if(digits) {
		do {
			if(*a++)
				return(0);
		}while(--digits);
	}

	return (1);
}

/* Assigns a = b. */

void XNN_Assign (XNN_DIGIT *a,XNN_DIGIT *b,unsigned int digits)
{
	if(digits) {
		do {
			*a++ = *b++;
		}while(--digits);
	}
}

/* Returns the significant length of a in digits. */

unsigned int XNN_Digits (XNN_DIGIT *a,unsigned int digits)
{

	if(digits) {
		digits--;

		do {
			if(*(a+digits))
				break;
		}while(digits--);

		return(digits + 1);
	}

	return(digits);
}

/* Computes a = b + c. Returns carry.

	 Lengths: a[digits], b[digits], c[digits].
 */
XNN_DIGIT XNN_Add (XNN_DIGIT *a, XNN_DIGIT *b, XNN_DIGIT *c, unsigned int digits)
{
	XNN_DIGIT temp, carry = 0;

	if(digits)
		do {
			if((temp = (*b++) + carry) < carry)
				temp = *c++;
            else {      /* Patch to prevent bug for Sun CC */
                if((temp += *c) < *c)
					carry = 1;
				else
					carry = 0;
                c++;
            }
			*a++ = temp;
		}while(--digits);

	return (carry);
}

#endif

static XNN_DIGIT subdigitmult(XNN_DIGIT *a, XNN_DIGIT *b, XNN_DIGIT c, XNN_DIGIT *d,unsigned int digits)
{
	XNN_DIGIT borrow, thigh, tlow;
	unsigned int i;

	borrow = 0;

	if(c != 0) {
		for(i = 0; i < digits; i++) {
			dmult(c, d[i], &thigh, &tlow);
			if((a[i] = b[i] - borrow) > (MAX_XNN_DIGIT - borrow))
				borrow = 1;
			else
				borrow = 0;
			if((a[i] -= tlow) > (MAX_XNN_DIGIT - tlow))
				borrow++;
			borrow += thigh;
		}
	}

	return (borrow);
}

/* Returns the significant length of a in bits, where a is a digit. */

static unsigned int XNN_DigitBits(XNN_DIGIT a)
{
	unsigned int i;

	for (i = 0; i < XNN_DIGIT_BITS; i++, a >>= 1)
		if (a == 0)
			break;

	return (i);
}

/* Computes a * b, result stored in high and low. */

static void dmult(XNN_DIGIT a,XNN_DIGIT b,XNN_DIGIT *high,XNN_DIGIT *low)
{
	XNN_HALF_DIGIT al, ah, bl, bh;
	XNN_DIGIT m1, m2, m, ml, mh, carry = 0;

	al = (XNN_HALF_DIGIT)LOW_HALF(a);
	ah = (XNN_HALF_DIGIT)HIGH_HALF(a);
	bl = (XNN_HALF_DIGIT)LOW_HALF(b);
	bh = (XNN_HALF_DIGIT)HIGH_HALF(b);

	*low = (XNN_DIGIT) al*bl;
	*high = (XNN_DIGIT) ah*bh;

	m1 = (XNN_DIGIT) al*bh;
	m2 = (XNN_DIGIT) ah*bl;
	m = m1 + m2;

	if(m < m1)
        carry = 1L << (XNN_DIGIT_BITS / 2);

	ml = (m & MAX_XNN_HALF_DIGIT) << (XNN_DIGIT_BITS / 2);
	mh = m >> (XNN_DIGIT_BITS / 2);

	*low += ml;

	if(*low < ml)
		carry++;

	*high += carry + mh;
}
static int XNN_IntstrMod2(unsigned char *in,int len,unsigned char *out)
{
	int i,j =0;
	unsigned char temp =0;
	unsigned char a;

	for(i=0; i<len;i++){
		a = temp*10+XNN_CHARTOINT(in[i]);
		if(a/2>0)
			out[j++] = XNN_INTTOCHAR(a/2);
		else
			out[j++] = XNN_INTTOCHAR(0);

		temp=a%2;
	}

	for(i=0;i<j;i++){
		if(out[i]!=0x30){
			XR_memcpy(&out[0],&out[i],j-i);
			break;
		}
	}

	return j-i;

}
int XNN_BigintstrToHexBytes(unsigned char *biginteger,unsigned char *outHexBytes)
{
	unsigned char bigint[1024]={0};
	unsigned char hexbytes[1024]={0};
	unsigned char temp[1024] ={0};
	unsigned char a;
	int i,len,le;

	i =0;
	le = 0;
	len = strlen((char*)biginteger);
	XR_memcpy(bigint,biginteger,len);

	while(len>0){
		a = XNN_CHARTOINT(bigint[len-1]);
		if(a%2>0){
			hexbytes[le]|=(1<<i);
		}
		i++;
		if(i>7){
			le++;
			i = 0;
		}
		len = XNN_IntstrMod2(bigint,len,temp);
		XR_memcpy(bigint,temp,len);
	}
	if(i!=0)
		le++;

	for(i = 0;i<le;i++){
		outHexBytes[i] = hexbytes[le-i-1];
	}
	return le;

}
