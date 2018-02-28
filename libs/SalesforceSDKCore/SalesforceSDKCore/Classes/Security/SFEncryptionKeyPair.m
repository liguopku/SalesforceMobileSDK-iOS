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

#import "SFEncryptionKeyPair.h"
#import "SFSDKCryptoUtils.h"

// NSCoding constants
static NSString * const kEncryptionPublicKeyCodingValue = @"com.salesforce.encryption.keypair.public";
static NSString * const kEncryptionPrivateKeyCodingValue = @"com.salesforce.encryption.keypair.private";

@implementation SFEncryptionKeyPair

@synthesize publicKey = _publicKey;
@synthesize privateKey = _privateKey;

- (id)initWithPublicKey:(NSData *)publicKeyData privateKey:(NSData *)privateKeyData
{
    self = [super init];
    if (self) {
        self.publicKey = publicKeyData;
        self.privateKey = privateKeyData;
    }
    return self;
}

- (id)initWithCoder:(NSCoder *)aDecoder
{
    self = [super init];
    if (self) {
        self.publicKey = [aDecoder decodeObjectForKey:kEncryptionPublicKeyCodingValue];
        self.privateKey = [aDecoder decodeObjectForKey:kEncryptionPrivateKeyCodingValue];
    }
    return self;
}

- (void)encodeWithCoder:(NSCoder *)aCoder
{
    [aCoder encodeObject:self.publicKey forKey:kEncryptionPublicKeyCodingValue];
    [aCoder encodeObject:self.privateKey forKey:kEncryptionPrivateKeyCodingValue];
}

- (id)copyWithZone:(NSZone *)zone
{
    SFEncryptionKeyPair *keyPairCopy = [[[self class] allocWithZone:zone] init];
    keyPairCopy.publicKey = [NSData dataWithData:self.publicKey];
    keyPairCopy.privateKey = [NSData dataWithData:self.privateKey];
    return keyPairCopy;
}

- (NSString *)publicKeyAsStringWithEncodeType:(SFEncryptionKeyEncodeType)encodeType
{
    return [self keyAsStringWithEncodeType:encodeType isPublicKey:true];
}

- (NSString *)privateKeyAsStringWithEncodeType:(SFEncryptionKeyEncodeType)encodeType
{
    return [self keyAsStringWithEncodeType:encodeType isPublicKey:false];
}

- (NSString *)keyAsStringWithEncodeType:(SFEncryptionKeyEncodeType)encodeType isPublicKey:(BOOL)isPublicKey
{
    NSData *keyData = isPublicKey ? self.publicKey : self.privateKey;
    if (encodeType == SFEncryptionKeyPairEncodeTypeBase64) {
        return [keyData base64EncodedStringWithOptions: 0];
    } else if (encodeType == SFEncryptionKeyPairEncodeTypeDER) {
        NSData *pemData = [SFSDKCryptoUtils getRSAPublicKeyAsDER:keyData];
        if (pemData != nil) {
            return [pemData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
        }
    }
    return nil;
}

- (BOOL)isEqual:(id)object
{
    if (object == self) return YES;
    if (object == nil || ![object isKindOfClass:[SFEncryptionKeyPair class]]) return NO;

    SFEncryptionKeyPair *objectAsKeyPair = (SFEncryptionKeyPair *)object;
    return ([self.publicKey isEqualToData:objectAsKeyPair.publicKey] && [self.privateKey isEqualToData:objectAsKeyPair.privateKey]);
}

- (NSUInteger)hash
{
    NSUInteger result = 43;
    result = 43 * result + [_publicKey hash];
    result = 43 * result + [_privateKey hash];
    return result;
}

@end

