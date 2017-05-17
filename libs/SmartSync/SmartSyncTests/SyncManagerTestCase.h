/*
 Copyright (c) 2017-present, salesforce.com, inc. All rights reserved.
 
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
#import <SalesforceSDKCore/SFUserAccountManager.h>
#import <SmartStore/SFSmartStore.h>
#import "SFSmartSyncSyncManager.h"

#define ACCOUNTS_SOUP       @"accounts"
#define ACCOUNT_TYPE        @"Account"
#define ID                  @"Id"
#define NAME                @"Name"
#define DESCRIPTION         @"Description"
#define LAST_MODIFIED_DATE  @"lastModifiedDate"
#define ATTRIBUTES          @"attributes"
#define TYPE                @"type"
#define RECORDS             @"records"
#define CONTACT_TYPE        @"Contact"
#define LAST_NAME           @"LastName"
#define CONTACTS_SOUP       @"contacts"
#define ACCOUNT_ID          @"AccountId"
#define CONTACT_TYPE_PLURAL @"Contacts"
#define TOTAL_SIZE_UNKNOWN  -2

@interface SyncManagerTestCase : XCTestCase

@property (nonatomic, strong) SFUserAccount* currentUser;
@property (nonatomic, strong) SFSmartSyncSyncManager* syncManager;
@property (nonatomic, strong) SFSmartStore* store;

- (NSString *)createRecordName:(NSString *)objectType;
- (NSString *)createAccountName;
- (NSString *)createDescription:(NSString *)name;
- (NSString*) createLocalId;
- (NSString *)buildInClause:(NSArray *)values;

- (NSArray<NSDictionary*>*) createAccountsLocally:(NSArray<NSString*>*)names;
- (void)createAccountsSoup;
- (void)dropAccountsSoup;
- (void)createContactsSoup;
- (void)dropContactsSoup;

- (NSArray*) buildFieldsMapForRecords:(NSUInteger)count objectType:(NSString*)objectType additionalFields:(NSDictionary*)additionalFields;
- (NSDictionary *)createAccountsOnServer:(NSUInteger)count;
- (void)deleteRecordsOnServer:(NSArray *)ids objectType:(NSString*)objectType;
- (NSDictionary *)sendSyncRequest:(SFRestRequest *)request;

- (NSInteger)trySyncDown:(SFSyncStateMergeMode)mergeMode target:(SFSyncDownTarget *)target soupName:(NSString *)soupName totalSize:(NSUInteger)totalSize numberFetches:(NSUInteger)numberFetches;
- (void)checkStatus:(SFSyncState *)sync expectedType:(SFSyncStateSyncType)expectedType expectedId:(NSInteger)expectedId expectedTarget:(SFSyncTarget *)expectedTarget expectedOptions:(SFSyncOptions *)expectedOptions expectedStatus:(SFSyncStateStatus)expectedStatus expectedProgress:(NSInteger)expectedProgress expectedTotalSize:(NSInteger)expectedTotalSize;
- (void)checkDb:(NSDictionary *)expectedIdToFields soupName:(NSString *)soupName;

- (void)checkDbStateFlags:(NSArray *)ids soupName:(NSString *)soupName expectedLocallyCreated:(bool)expectedLocallyCreated expectedLocallyUpdated:(bool)expectedLocallyUpdated expectedLocallyDeleted:(bool)expectedLocallyDeleted;

- (NSDictionary *)makeSomeLocalChanges:(NSDictionary *)idToFields soupName:(NSString *)soupName;
- (NSDictionary *)makeSomeLocalChanges:(NSDictionary *)idToFields soupName:(NSString *)soupName idsToUpdate:(NSArray *)idsToUpdate;
- (NSDictionary *)prepareSomeChanges:(NSDictionary *)idToFields idsToUpdate:(NSArray *)idsToUpdate suffix:(NSString *)suffix;
@end
