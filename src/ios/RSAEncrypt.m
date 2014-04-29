//
//  RSAEncrypt.m
//  xFace
//
//  Created by hejp raul on 12-5-17.
//  Copyright (c) 2012年 Polyvi Inc. All rights reserved.
//

#import "RSAEncrypt.h"

@implementation RSAEncrypt
@synthesize moudulus;
@synthesize exmod;

#define RSA_MAX_DATA_LEN 1024

-(id)init
{
    if (self = [super init])
    {
        [self setExmod:[[NSString alloc] init]];
        [self setMoudulus:[[NSString alloc] init]];
    }

    return self;
}


-(void)dealloc
{
    if (self) {
        [moudulus release];
        [exmod release];
    }

    [super dealloc];
}

/**
 初始化指数、模数
 @param inMod   公钥模数
 @param inExmod 公钥指数
 @returns 成功返回RSAEncrypt对象，否则返回nil
 */
-(id)initWithMod:(NSString *)inMod exmod:(NSString *)inExmod
{
    if (self = [super init])
    {
        [self setExmod:[[NSString alloc] initWithString:inExmod]];
        [self setMoudulus:[[NSString alloc] initWithString:inMod]];
    }

    return self;
}

/**
 RSA公钥加密
 @param inStr   被加密的明文数据
 @param inLen   被加密明文数据长度
 @returns 成功返回加密后密文数据，否则返回nil
 */
-(NSString *)RSAPublicEncryptString:(NSString *) inStr length:(NSInteger) inLen
{
    NSInteger ret = -1;
    unsigned int outLen = 0;
    char tempStr[RSA_MAX_DATA_LEN] = {0};
    char tempOutStr[RSA_MAX_DATA_LEN] = {0};

    if (![self moudulus] || ![self exmod] || !inStr)
    {
        return nil;
    }

    ret = XRSA_PublicEncrypt([moudulus UTF8String], [exmod UTF8String], [inStr UTF8String], inLen,
                            tempStr, &outLen);
    if (ret != 0)
        return nil;

    RSA_hexEncode(tempStr, outLen, tempOutStr);
    NSString *outStr = [NSString stringWithCString:tempOutStr];
    return outStr;
}
#define RSA_TEST_PRMOD @"304FDBE211218BCD9F1BDCB1E1BFB00885E1E5FB012282EA23AA88C40CDF764423B5AE4A156915CB7732AE9A4B5B2090A6400EF1EAB7211A3262AE0F770C54D5648CED58B18709F34C89A0CDFDE91616A4ECBF7A8061EA1DA189BEF7C712389A42090B0F5CBB8006664A8542FA3637A45470FF59C8F467127435A79BBBB4247"
/**
 RSA公钥加密
 @param inStr   被解密的密文数据
 @param inLen   被解密密文数据长度
 @returns 成功返回解密后的密文数据，否则返回nil
 */
-(NSString *)RSAPublicDecryptString:(NSString *) inStr length:(NSInteger) inLen
{
    NSInteger ret = -1;
    unsigned int outLen = 0;
    int tempInLen = 0;
    char tempInstr[RSA_MAX_DATA_LEN] = {0};
    char tempOutStr[RSA_MAX_DATA_LEN] = {0};
    NSString *prMod = [[NSString alloc] initWithString:RSA_TEST_PRMOD];

    if (![self moudulus] || ![self exmod] || !inStr)
    {
        return nil;
    }

    tempInLen = RSA_hexDecode([inStr UTF8String], inLen, tempInstr);

    ret = XRSA_PublicDecrypt([prMod UTF8String], [exmod UTF8String], tempInstr, tempInLen,
                            tempOutStr, &outLen);
    if (ret != 0)
        return nil;

    NSString *outStr = [NSString stringWithCString:tempOutStr];
    return outStr;
}

@end
