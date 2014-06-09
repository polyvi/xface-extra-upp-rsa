//
//  RSAEncrypt.m
//  xFace
//
//  Created by hejp raul on 12-5-17.
//  Copyright (c) 2012年 Polyvi Inc. All rights reserved.
//
#import "RSAEncrypt.h"
#import "Rsa.h"
#import "UPPUtil.h"

@implementation RSACrypt

#define RSA_MAX_DATA_LEN 1024

-(void)dealloc {
    [_modulus release];
    [_exponent release];
    [super dealloc];
}

/**
 初始化指数、模数
 @param inMod   公钥模数
 @param inExmod 公钥指数
 @returns 成功返回RSAEncrypt对象，否则返回nil
 */

-(id)initWithModulus:(NSString *)modulus exponent:(NSString *)exponent {
    if (self = [super init]) {
        [self setModulus:modulus];
        [self setExponent:exponent];
    }
    return self;
}

/**
 RSA公钥加密
 @param inStr   被加密的明文数据
 @returns 成功返回加密后密文数据，否则返回nil
 */
-(NSString *)RSAPublicEncryptString:(NSString *) inStr {
    if (!self.modulus || !self.exponent || !inStr) {
        return nil;
    }

    NSInteger ret = -1;
    unsigned int outLen = 0;
    char tempStr[RSA_MAX_DATA_LEN] = {0};
    char tempOutStr[RSA_MAX_DATA_LEN] = {0};
    char realInStr[RSA_MAX_DATA_LEN] = {0};
    unsigned int realLen = 0;

    realLen = RSA_hexDecode((char *)[inStr UTF8String], [inStr length], realInStr);
    ret = XRSA_PublicEncrypt([self.modulus UTF8String], [self.exponent UTF8String], realInStr, realLen, tempStr, &outLen);
    if (ret != 0)
        return nil;

    RSA_hexEncode(tempStr, outLen, tempOutStr);
    NSString *outStr = [NSString stringWithCString:tempOutStr encoding:NSUTF8StringEncoding];
    return outStr;
}

@end
