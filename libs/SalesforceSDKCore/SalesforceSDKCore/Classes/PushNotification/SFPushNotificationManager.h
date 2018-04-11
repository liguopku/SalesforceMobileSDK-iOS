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

#import <Foundation/Foundation.h>
#import <SalesforceSDKCore/SalesforceSDKConstants.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString * const kSFPushNotificationKeyName;

@class SFUserAccount;

/** Handles push notification registration and unregistration, both for Salesforce notifications and remote notifications.
 */
@interface SFPushNotificationManager : NSObject

/** Device token returned when registering with APNS.
 */
@property (nonatomic, strong) NSString* deviceToken;

/** ID returned when registering for Salesforce push notifications.
 */
@property (nonatomic, strong) NSString* deviceSalesforceId;

/** The share instance of this class.
 */
+ (SFPushNotificationManager *) sharedInstance;


/**
 * Register with APNS
 */
- (void)registerForRemoteNotifications;

/**
 * Call this method from your app delegate's didRegisterForRemoteNotificationsWithDeviceToken
 * @param deviceTokenData The device token returned by APNS.
 */
- (void)didRegisterForRemoteNotificationsWithDeviceToken:(NSData*)deviceTokenData;

/**
 * Register for notifications with Salesforce.
 * Call this method after authenticating with Salesforce and registering with APNS.
 * @return YES for successful registration call made.
 */
- (BOOL)SFSDK_DEPRECATED(6.1, 7.0, "Use 'registerSalesforceNotificationsWithCompletionBlock:failBlock' instead.") registerForSalesforceNotifications;

/**
 * Register for notifications with Salesforce.
 * Call this method after authenticating with Salesforce and registering with APNS.
 * @param completionBlock Completion block.
 * @param failBlock fail block.
 * @return YES for successful registration call being made.
 */
- (BOOL)registerSalesforceNotificationsWithCompletionBlock:(nullable void (^)(void))completionBlock failBlock:(nullable void (^)(void))failBlock;

/**
 * Unregister from notifications with Salesforce for all users. This method is called at logout.
 * @return YES for successful unregistration call being made.
 */
- (BOOL) SFSDK_DEPRECATED(6.1, 7.0, "Use 'unregisterSalesforceNotificationsWithCompletionBlock' instead.") unregisterSalesforceNotifications;

/**
 * Unregister from notifications with Salesforce for a specific user. This method is called at logout.
 * @param user User account.
 * @return YES for successful unregistration call being made.
 */
- (BOOL) SFSDK_DEPRECATED(6.1, 7.0, "Use 'unregisterSalesforceNotificationsWithCompletionBlock' instead.") unregisterSalesforceNotifications:(SFUserAccount*)user;

/**
 * Unregister from notifications with Salesforce for a specific user. This method is called at logout.
 * @param user User account.
 * @param completionBlock Completion block.
 * @return YES for successful unregistration call being made.
 */
- (BOOL)unregisterSalesforceNotificationsWithCompletionBlock:(SFUserAccount*)user completionBlock:(nullable void (^)(void))completionBlock;

@end

NS_ASSUME_NONNULL_END
