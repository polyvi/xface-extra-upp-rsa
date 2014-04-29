//
//  RSAEncrypt.h
//  xFace
//
//  Created by hejp raul on 12-5-17.
//  Copyright (c) 2012年 Polyvi Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Rsa.h"
#import "UPPUtil.h"

@interface RSAEncrypt : NSObject
{
    NSString *modulus;  /**< 公钥模数 */
    NSString *exmod;    /**< 公钥指数 */
}

/**
 初始化指数、模数
 @param inMod   公钥模数
 @param inExmod 公钥指数
 @returns 成功返回RSAEncrypt对象，否则返回nil
 */
-(id)initWithMod:(NSString *)inMod exmod:(NSString *)inExmod;

/**
 RSA公钥加密
 @param inStr   被加密的明文数据
 @param inLen   被加密明文数据长度
 @returns 成功返回加密后密文数据，否则返回nil
 */
-(NSString *)RSAPublicEncryptString:(NSString *) len length:(NSInteger) inLen;

/**
 RSA公钥加密
 @param inStr   被解密的密文数据
 @param inLen   被解密密文数据长度
 @returns 成功返回解密后的密文数据，否则返回nil
 */
-(NSString *)RSAPublicDecryptString:(NSString *) instr length:(NSInteger) inLen;

@property(strong,nonatomic) NSString *moudulus;
@property(strong,nonatomic) NSString *exmod;
@end
