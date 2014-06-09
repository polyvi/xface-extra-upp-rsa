//
//  RSAEncrypt.h
//  xFace
//
//  Created by hejp raul on 12-5-17.
//  Copyright (c) 2012年 Polyvi Inc. All rights reserved.
//
#import <Foundation/Foundation.h>

@interface RSACrypt : NSObject
@property(retain,nonatomic) NSString *modulus;
@property(retain,nonatomic) NSString *exponent;

/**
 初始化指数、模数
 @param inMod   公钥模数
 @param inExmod 公钥指数
 @returns 成功返回RSAEncrypt对象，否则返回nil
 */
-(id)initWithModulus:(NSString *)modulus exponent:(NSString *)exponent;

/**
 RSA公钥加密
 @param inStr   被加密的明文数据
 @returns 成功返回加密后密文数据，否则返回nil
 */
-(NSString *)RSAPublicEncryptString:(NSString *)inStr;

@end