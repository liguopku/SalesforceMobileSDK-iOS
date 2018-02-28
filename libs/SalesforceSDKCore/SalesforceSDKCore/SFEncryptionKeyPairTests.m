/*
 Copyright (c) 2014-present, salesforce.com, inc. All rights reserved.
 
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
#import "SFEncryptionKeyPair.h"


@interface SFEncryptionKeyPairTests : XCTestCase

@end

@implementation SFEncryptionKeyPairTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

- (void)testKeyPairEquality
{
    SFEncryptionKeyPair *keyPair1 = [[SFEncryptionKeyPair alloc] initWithPublicKey:[@"publicKeyData" dataUsingEncoding:NSUTF8StringEncoding] privateKey:[@"privateKeyData" dataUsingEncoding:NSUTF8StringEncoding]];
    SFEncryptionKeyPair *keyPair2 = [[SFEncryptionKeyPair alloc] initWithPublicKey:[@"publicKeyData" dataUsingEncoding:NSUTF8StringEncoding] privateKey:[@"privateKeyData" dataUsingEncoding:NSUTF8StringEncoding]];
    SFEncryptionKeyPair *keyPair3 = [[SFEncryptionKeyPair alloc] initWithPublicKey:[@"otherPublicKeyData" dataUsingEncoding:NSUTF8StringEncoding] privateKey:[@"otherPrivateKeyData" dataUsingEncoding:NSUTF8StringEncoding]];
    XCTAssertEqualObjects(keyPair1, keyPair2, @"Objects should be equal, with identical public and private keys.");
    XCTAssertNotEqualObjects(keyPair1, keyPair3, @"Object with different public and private keys should not be equal.");
}


- (void)testKeyPairStringRepresentationsBase64
{
    SFEncryptionKeyPair *keyPair1 = [[SFEncryptionKeyPair alloc] initWithPublicKey:[@"publicKeyData" dataUsingEncoding:NSUTF8StringEncoding] privateKey:[@"privateKeyData" dataUsingEncoding:NSUTF8StringEncoding]];
    SFEncryptionKeyPair *keyPair2 = [[SFEncryptionKeyPair alloc] initWithPublicKey:[@"publicKeyData" dataUsingEncoding:NSUTF8StringEncoding] privateKey:[@"privateKeyData" dataUsingEncoding:NSUTF8StringEncoding]];
    XCTAssertEqualObjects([keyPair1 publicKeyAsStringWithEncodeType:SFEncryptionKeyPairEncodeTypeBase64], [keyPair2 publicKeyAsStringWithEncodeType:SFEncryptionKeyPairEncodeTypeBase64], @"Public Key string representation with default base64 encode should be the same.");
    XCTAssertEqualObjects([keyPair1 privateKeyAsStringWithEncodeType:SFEncryptionKeyPairEncodeTypeBase64], [keyPair2 privateKeyAsStringWithEncodeType:SFEncryptionKeyPairEncodeTypeBase64], @"Private Key string representation with default base64 encode should be the same.");
}

- (void)testKeyPairStringRepresentationsDER
{
    SFEncryptionKeyPair *keyPair1 = [[SFEncryptionKeyPair alloc] initWithPublicKey:[@"publicKeyData" dataUsingEncoding:NSUTF8StringEncoding] privateKey:[@"privateKeyData" dataUsingEncoding:NSUTF8StringEncoding]];
    SFEncryptionKeyPair *keyPair2 = [[SFEncryptionKeyPair alloc] initWithPublicKey:[@"publicKeyData" dataUsingEncoding:NSUTF8StringEncoding] privateKey:[@"privateKeyData" dataUsingEncoding:NSUTF8StringEncoding]];
    XCTAssertEqualObjects([keyPair1 publicKeyAsStringWithEncodeType:SFEncryptionKeyPairEncodeTypeDER], [keyPair2 publicKeyAsStringWithEncodeType:SFEncryptionKeyPairEncodeTypeDER], @"Public Key string representation with DER base64 encode should be the same.");
    XCTAssertEqualObjects([keyPair1 privateKeyAsStringWithEncodeType:SFEncryptionKeyPairEncodeTypeDER], [keyPair2 privateKeyAsStringWithEncodeType:SFEncryptionKeyPairEncodeTypeDER], @"Private Key string representation with DER base64 encode should be the same.");
}

@end

