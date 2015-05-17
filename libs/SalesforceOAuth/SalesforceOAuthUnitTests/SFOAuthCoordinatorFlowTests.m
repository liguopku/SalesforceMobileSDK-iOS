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

#import <UIKit/UIKit.h>
#import <XCTest/XCTest.h>
#import <SalesforceSDKCommon/SFSDKAsyncProcessListener.h>

#import "SFOAuthCoordinator+Internal.h"
#import "SFOAuthFlowAndDelegate.h"

@interface SFOAuthCoordinatorFlowTests : XCTestCase

@property (nonatomic, strong) SFOAuthCoordinator *coordinator;
@property (nonatomic, strong) SFOAuthFlowAndDelegate *flowAndDelegate;

@end

@implementation SFOAuthCoordinatorFlowTests

- (void)setUp {
    [super setUp];
    [SFLogger setLogLevel:SFLogLevelDebug];
    [self setupCoordinatorFlow];
}

- (void)tearDown {
    [self tearDownCoordinatorFlow];
    [super tearDown];
}

- (void)testUserAgentFlowInitiated {
    [self.coordinator authenticate];
    SFSDKAsyncProcessListener *listener = [[SFSDKAsyncProcessListener alloc] initWithExpectedStatus:@YES
                                                                                  actualStatusBlock:^id{
                                                                                      return [NSNumber numberWithBool:self.flowAndDelegate.didAuthenticateCalled];
                                                                                  }
                                                                                            timeout:(self.flowAndDelegate.timeBeforeUserAgentCompletion + 0.5)];
    BOOL userAgentFlowSucceeded = [[listener waitForCompletion] boolValue];
    XCTAssertTrue(userAgentFlowSucceeded, @"User agent flow should have completed successfully.");
    XCTAssertTrue(self.flowAndDelegate.beginUserAgentFlowCalled, @"User agent flow should have been called in first authenticate.");
    XCTAssertFalse(self.flowAndDelegate.beginTokenEndpointFlowCalled, @"Token endpoint should not have been called in first authenticate.");
    XCTAssertEqual(self.flowAndDelegate.tokenEndpointFlowType, SFOAuthTokenEndpointFlowNone, @"Should be no token endpoint flow type configured.");
}

- (void)testRefreshFlowInitiated {
    self.coordinator.credentials.refreshToken = @"YeahIHaveATokenWoo!";
    [self.coordinator authenticate];
    SFSDKAsyncProcessListener *listener = [[SFSDKAsyncProcessListener alloc] initWithExpectedStatus:@YES
                                                                                  actualStatusBlock:^id{
                                                                                      return [NSNumber numberWithBool:self.flowAndDelegate.didAuthenticateCalled];
                                                                                  }
                                                                                            timeout:(self.flowAndDelegate.timeBeforeUserAgentCompletion + 0.5)];
    BOOL refreshFlowSucceeded = [[listener waitForCompletion] boolValue];
    XCTAssertTrue(refreshFlowSucceeded, @"Refresh flow should have completed successfully.");
    XCTAssertFalse(self.flowAndDelegate.beginUserAgentFlowCalled, @"User agent flow should not have been called with a refresh token.");
    XCTAssertTrue(self.flowAndDelegate.beginTokenEndpointFlowCalled, @"Token endpoint should have been called with a refresh token.");
    XCTAssertEqual(self.flowAndDelegate.tokenEndpointFlowType, SFOAuthTokenEndpointFlowRefresh, @"Token endpoint flow type should be refresh.");
}

- (void)testMultipleAuthenticationRequests {
    [self.coordinator authenticate];
    XCTAssertTrue(self.flowAndDelegate.beginUserAgentFlowCalled, @"User agent flow should have been called in first authenticate.");
    XCTAssertFalse(self.flowAndDelegate.beginTokenEndpointFlowCalled, @"Token endpoint should not have been called in first authenticate.");
    XCTAssertEqual(self.flowAndDelegate.tokenEndpointFlowType, SFOAuthTokenEndpointFlowNone, @"Should be no token endpoint flow type configured.");
    
    [self configureFlowAndDelegate];
    [self.coordinator authenticate];
    XCTAssertFalse(self.flowAndDelegate.beginUserAgentFlowCalled, @"User agent flow should not have been called in second authenticate.");
    XCTAssertFalse(self.flowAndDelegate.beginTokenEndpointFlowCalled, @"Token endpoint should not have been called in second authenticate.");
    XCTAssertEqual(self.flowAndDelegate.tokenEndpointFlowType, SFOAuthTokenEndpointFlowNone, @"Should be no token endpoint flow type configured.");
}

#pragma mark - Private methods

- (void)setupCoordinatorFlow {
    NSString *credsIdentifier = [NSString stringWithFormat:@"CredsIdentifier_%u", arc4random()];
    NSString *credsClientId = [NSString stringWithFormat:@"CredsClientId_%u", arc4random()];
    SFOAuthCredentials *creds = [[SFOAuthCredentials alloc] initWithIdentifier:credsIdentifier clientId:credsClientId encrypted:YES];
    creds.redirectUri = [NSString stringWithFormat:@"sfdcUnitTest:///redirect_uri_%u", arc4random()];
    self.coordinator = [[SFOAuthCoordinator alloc] initWithCredentials:creds];
    [self configureFlowAndDelegate];
}

- (void)configureFlowAndDelegate {
    self.flowAndDelegate = [[SFOAuthFlowAndDelegate alloc] initWithCoordinator:self.coordinator];
    self.coordinator.oauthCoordinatorFlow = self.flowAndDelegate;
    self.coordinator.delegate = self.flowAndDelegate;
}

- (void)tearDownCoordinatorFlow {
    [self.coordinator.credentials revoke];
    self.coordinator.delegate = nil;
    self.coordinator.oauthCoordinatorFlow = nil;
    self.flowAndDelegate = nil;
    self.coordinator = nil;
}

@end
