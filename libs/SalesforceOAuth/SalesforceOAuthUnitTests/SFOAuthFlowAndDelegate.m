/*
 Copyright (c) 2015, salesforce.com, inc. All rights reserved.
 
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

#import "SFOAuthFlowAndDelegate.h"
#import "SFOAuthOrgAuthConfiguration.h"
#import "SFOAuthInfo.h"

static NSString * const kWebNotSupportedExceptionName = @"com.salesforce.oauth.tests.WebNotSupported";
static NSString * const kWebNotSupportedReasonFormat  = @"%@ UIWebView transactions not supported in unit test framework.";

@interface SFOAuthFlowAndDelegate ()

@property (nonatomic, weak) SFOAuthCoordinator *coordinator;
@property (nonatomic, strong) SFOAuthOrgAuthConfiguration *retrieveOrgConf;
@property (nonatomic, strong) NSError *retrieveOrgConfError;

@end

@implementation SFOAuthFlowAndDelegate

@synthesize coordinator = _coordinator;

- (id)initWithCoordinator:(SFOAuthCoordinator *)coordinator {
    self = [super init];
    if (self) {
        self.coordinator = coordinator;
        self.isNetworkAvailable = YES;  // Network is available by default.
        self.timeBeforeUserAgentCompletion = 1.0;  // 1s default before user agent flow "completes".
        self.userAgentFlowIsSuccessful = YES;
    }
    return self;
}

- (void)setRetrieveOrgAuthConfigurationData:(SFOAuthOrgAuthConfiguration *)config error:(NSError *)error {
    self.retrieveOrgConf = config;
    self.retrieveOrgConfError = error;
}

#pragma mark - Private methods

- (NSURL *)userAgentSuccessUrl {
    NSString *successFormatString = @"%@#access_token=%@&issued_at=%@&instance_url=%@&id=%@";
    NSString *successUrl = [NSString stringWithFormat:successFormatString,
                            self.coordinator.credentials.redirectUri,
                            @"some_access_token_val",
                            @(1418945872705),
                            [@"https://na1.salesforce.com" stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding],
                            [@"https://login.salesforce.com/id/some_org_id/some_user_id" stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]
                            ];
    return [NSURL URLWithString:successUrl];
}

- (NSURL *)userAgentErrorUrl {
    NSString *errorFormatString = @"%@#error=%@&error_description=%@";
    NSString *errorUrl = [NSString stringWithFormat:errorFormatString,
                          self.coordinator.credentials.redirectUri,
                          @"user_agent_flow_error_from_unit_test",
                          [@"User agent flow error from unit test" stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]
                          ];
    return [NSURL URLWithString:errorUrl];
}

#pragma mark - SFOAuthCoordinatorFlow

- (void)beginUserAgentFlow {
    [self log:SFLogLevelDebug format:@"%@ called.", NSStringFromSelector(_cmd)];
    self.beginUserAgentFlowCalled = YES;
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(self.timeBeforeUserAgentCompletion * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if (self.userAgentFlowIsSuccessful) {
        [self.coordinator handleUserAgentResponse:[self userAgentSuccessUrl]];
        } else {
            [self.coordinator handleUserAgentResponse:[self userAgentErrorUrl]];
        }
    });
    [self.coordinator performSelector:@selector(handleUserAgentResponse:) withObject:[self userAgentSuccessUrl] afterDelay:self.timeBeforeUserAgentCompletion];
}

- (void)beginTokenEndpointFlow:(SFOAuthTokenEndpointFlow)flowType {
    [self log:SFLogLevelDebug format:@"%@ called.", NSStringFromSelector(_cmd)];
    self.beginTokenEndpointFlowCalled = YES;
    self.tokenEndpointFlowType = flowType;
}

- (void)beginNativeBrowserFlow {
    [self log:SFLogLevelDebug format:@"%@ called.", NSStringFromSelector(_cmd)];
    self.beginNativeBrowserFlowCalled = YES;
}

- (void)retrieveOrgAuthConfiguration:(void (^)(SFOAuthOrgAuthConfiguration *orgAuthConfig, NSError *error))retrievedAuthConfigBlock {
    [self log:SFLogLevelDebug format:@"%@ called.", NSStringFromSelector(_cmd)];
    if (retrievedAuthConfigBlock) {
        retrievedAuthConfigBlock(self.retrieveOrgConf, self.retrieveOrgConfError);
    }
}

- (void)handleTokenEndpointResponse {
    [self log:SFLogLevelDebug format:@"%@ called.", NSStringFromSelector(_cmd)];
    self.handleTokenEndpointResponseCalled = YES;
}

#pragma mark - SFOAuthCoordinatorDelegate

- (void)oauthCoordinator:(SFOAuthCoordinator *)coordinator didBeginAuthenticationWithView:(UIWebView *)view {
    [self log:SFLogLevelDebug format:@"%@ called.", NSStringFromSelector(_cmd)];
    NSString *reason = [NSString stringWithFormat:kWebNotSupportedReasonFormat, NSStringFromSelector(_cmd)];
    @throw [NSException exceptionWithName:kWebNotSupportedExceptionName reason:reason userInfo:nil];
}

- (void)oauthCoordinator:(SFOAuthCoordinator *)coordinator willBeginAuthenticationWithView:(UIWebView *)view {
    [self log:SFLogLevelDebug format:@"%@ called.", NSStringFromSelector(_cmd)];
    NSString *reason = [NSString stringWithFormat:kWebNotSupportedReasonFormat, NSStringFromSelector(_cmd)];
    @throw [NSException exceptionWithName:kWebNotSupportedExceptionName reason:reason userInfo:nil];
}

- (void)oauthCoordinator:(SFOAuthCoordinator *)coordinator didStartLoad:(UIWebView *)view {
    [self log:SFLogLevelDebug format:@"%@ called.", NSStringFromSelector(_cmd)];
    NSString *reason = [NSString stringWithFormat:kWebNotSupportedReasonFormat, NSStringFromSelector(_cmd)];
    @throw [NSException exceptionWithName:kWebNotSupportedExceptionName reason:reason userInfo:nil];
}

- (void)oauthCoordinator:(SFOAuthCoordinator *)coordinator didFinishLoad:(UIWebView *)view error:(NSError*)errorOrNil {
    [self log:SFLogLevelDebug format:@"%@ called.", NSStringFromSelector(_cmd)];
    NSString *reason = [NSString stringWithFormat:kWebNotSupportedReasonFormat, NSStringFromSelector(_cmd)];
    @throw [NSException exceptionWithName:kWebNotSupportedExceptionName reason:reason userInfo:nil];
}

- (void)oauthCoordinatorWillBeginAuthentication:(SFOAuthCoordinator *)coordinator authInfo:(SFOAuthInfo *)info {
    [self log:SFLogLevelDebug format:@"%@ called.", NSStringFromSelector(_cmd)];
    self.willBeginAuthenticationCalled = YES;
    self.authInfo = info;
}

- (void)oauthCoordinatorDidAuthenticate:(SFOAuthCoordinator *)coordinator authInfo:(SFOAuthInfo *)info {
    [self log:SFLogLevelDebug format:@"%@ called.", NSStringFromSelector(_cmd)];
    self.didAuthenticateCalled = YES;
    self.authInfo = info;
}

- (void)oauthCoordinator:(SFOAuthCoordinator *)coordinator didFailWithError:(NSError *)error authInfo:(SFOAuthInfo *)info {
    [self log:SFLogLevelDebug format:@"%@ called.", NSStringFromSelector(_cmd)];
    self.didFailWithErrorCalled = YES;
    self.didFailWithError = error;
    self.authInfo = info;
}

- (BOOL)oauthCoordinatorIsNetworkAvailable:(SFOAuthCoordinator*)coordinator {
    [self log:SFLogLevelDebug format:@"%@ called.", NSStringFromSelector(_cmd)];
    self.isNetworkAvailableCalled = YES;
    return self.isNetworkAvailable;
}

@end
