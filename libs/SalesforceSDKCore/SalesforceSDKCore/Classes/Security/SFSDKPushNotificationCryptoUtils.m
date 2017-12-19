/*
 Copyright (c) 2013-present, salesforce.com, inc. All rights reserved.
 
 Redistribution and use of this software in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this list of conditions
 and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of
 conditions and the following disclaimer in the documentation and/or other materials provided
 with the distribution.
 * Neither the name of salesforce.com, inc. nor the names of its contributors may be used to
 endorse or promote products derived from this software without specific prior written
 permission of salesforce.com, inc.
 
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
 WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#import "SFSDKPushNotificationCryptoUtils.h"
#import <CommonCrypto/CommonCrypto.h>

@interface SFSDKPushNotificationCryptoUtils ()

/**
 Executes the encryption/decryption operation (depending on the configuration of the cryptor).
 @param inData The data to encrypt/decrypt.
 @param cryptor The CCCryptor doing the encryption/decryption.
 @param resultData Output parameter containing the encrypted/decrypted result of the operation.
 @return YES if the operation was successful, NO otherwise.
 */
+ (BOOL)executeCrypt:(NSData *)inData cryptor:(CCCryptorRef)cryptor resultData:(NSData **)resultData;

@end

@implementation SFSDKPushNotificationCryptoUtils

+ (NSData *)aes128EncryptData:(NSData *)data withKey:(NSData *)key iv:(NSData *)iv
{
    // Ensure the proper key, IV sizes.
    if (key == nil) {
        [SFSDKCoreLogger e:[self class] format:@"aes128EncryptData: encryption key is nil.  Cannot encrypt data."];
        return nil;
    }
    NSMutableData *mutableKey = [key mutableCopy];
    [mutableKey setLength:kCCBlockSizeAES128];
    NSMutableData *mutableIv = [iv mutableCopy];
    [mutableIv setLength:kCCBlockSizeAES128];
    
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus status = CCCryptorCreate(kCCEncrypt,
                                             kCCAlgorithmAES,
                                             kCCOptionPKCS7Padding,
                                             [mutableKey bytes],
                                             [mutableKey length],
                                             [mutableIv bytes],
                                             &cryptor);
    if (status != kCCSuccess) {
        [SFSDKCoreLogger e:[self class] format:@"Error creating encryption cryptor with CCCryptorCreate().  Status code: %d", status];
        return nil;
    }
    
    NSData *resultData = nil;
    BOOL executeCryptSuccess = [self executeCrypt:data cryptor:cryptor resultData:&resultData];
    CCCryptorRelease(cryptor);
    return (executeCryptSuccess ? resultData : nil);
}

+ (NSData *)aes128DecryptData:(NSData *)data withKey:(NSData *)key iv:(NSData *)iv
{
    // Ensure the proper key, IV sizes.
    if (key == nil) {
        [SFSDKCoreLogger e:[self class] format:@"aes128DecryptData: decryption key is nil.  Cannot decrypt data."];
        return nil;
    }
    NSMutableData *mutableKey = [key mutableCopy];
    [mutableKey setLength:kCCBlockSizeAES128];
    NSMutableData *mutableIv = [iv mutableCopy];
    [mutableIv setLength:kCCBlockSizeAES128];
    
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus status = CCCryptorCreate(kCCDecrypt,
                                             kCCAlgorithmAES,
                                             kCCOptionPKCS7Padding,
                                             [mutableKey bytes],
                                             [mutableKey length],
                                             [mutableIv bytes],
                                             &cryptor);
    if (status != kCCSuccess) {
        [SFSDKCoreLogger e:[self class] format:@"Error creating decryption cryptor with CCCryptorCreate().  Status code: %d", status];
        return nil;
    }
    
    NSData *resultData = nil;
    BOOL executeCryptSuccess = [self executeCrypt:data cryptor:cryptor resultData:&resultData];
    CCCryptorRelease(cryptor);
    return (executeCryptSuccess ? resultData : nil);
}

#pragma mark - Private methods

+ (BOOL)executeCrypt:(NSData *)inData cryptor:(CCCryptorRef)cryptor resultData:(NSData **)resultData
{
    size_t buffersize = CCCryptorGetOutputLength(cryptor, (size_t)[inData length], true);
    void *buffer = malloc(buffersize);
    size_t bufferused = 0;
    size_t totalbytes = 0;
    CCCryptorStatus status = CCCryptorUpdate(cryptor, [inData bytes], (size_t)[inData length], buffer, buffersize, &bufferused);
    if (status != kCCSuccess) {
        [SFSDKCoreLogger e:[self class] format:@"CCCryptorUpdate() failed with status code: %d", status];
        free(buffer);
        return NO;
    }
    
    totalbytes += bufferused;
    
    status = CCCryptorFinal(cryptor, buffer + bufferused, buffersize - bufferused, &bufferused);
    if (status != kCCSuccess) {
        [SFSDKCoreLogger e:[self class] format:@"CCCryptoFinal() failed with status code: %d", status];
        free(buffer);
        return NO;
    }
    
    totalbytes += bufferused;
    
    if (resultData != nil)
        *resultData = [NSData dataWithBytesNoCopy:buffer length:totalbytes];
        else
            free(buffer);
            
            return YES;
}

@end
