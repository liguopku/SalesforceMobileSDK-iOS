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

#import <XCTest/XCTest.h>
#import "SFSDKPushNotificationCryptoUtils.h"

@interface SFSDKPushNotificationCryptoUtilsTests : XCTestCase

@end

@implementation SFSDKPushNotificationCryptoUtilsTests

- (void)testAes128EncryptionDecryption
{
    NSData *origData = [@"The quick brown fox..." dataUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [@"My encryption key" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ivData = [@"Here's an iv staging string" dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *encryptedData = [SFSDKPushNotificationCryptoUtils aes128EncryptData:origData withKey:keyData iv:ivData];
    XCTAssertFalse([encryptedData isEqualToData:origData], @"Encrypted data should not be the same as original data.");
    
    // Clean decryption should pass.
    NSData *decryptedData = [SFSDKPushNotificationCryptoUtils aes128DecryptData:encryptedData withKey:keyData iv:ivData];
    XCTAssertTrue([decryptedData isEqualToData:origData], @"Decrypted data should match original data.");
    
    // Bad decryption key data should return different data.
    NSData *badKey = [@"The wrong key" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *badIv = [@"The wrong iv" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *badDecryptData = [SFSDKPushNotificationCryptoUtils aes128DecryptData:encryptedData withKey:badKey iv:ivData];
    XCTAssertFalse([badDecryptData isEqualToData:origData], @"Wrong encryption key should return different data on decrypt.");
    badDecryptData = [SFSDKPushNotificationCryptoUtils aes128DecryptData:encryptedData withKey:keyData iv:badIv];
    XCTAssertFalse([badDecryptData isEqualToData:origData], @"Wrong initialization vector should return different data on decrypt.");
    badDecryptData = [SFSDKPushNotificationCryptoUtils aes128DecryptData:encryptedData withKey:badKey iv:badIv];
    XCTAssertFalse([badDecryptData isEqualToData:origData], @"Wrong key and initialization vector should return different data on decrypt.");
}

@end
