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

#import "SFSmartSyncSyncManager.h"
#import "SFSmartSyncConstants.h"
#import "SFSmartSyncObjectUtils.h"
#import <SalesforceSDKCore/SFAuthenticationManager.h>
#import <SalesforceSDKCore/SFUserAccount.h>
#import <SmartStore/SFSmartStore.h>
#import <SmartStore/SFQuerySpec.h>
#import <SalesforceSDKCore/SFJsonUtils.h>
#import <SalesforceSDKCore/SalesforceSDKManager.h>
#import <SalesforceSDKCore/SFSDKEventBuilderHelper.h>

// Page size
NSUInteger const kSyncManagerPageSize = 2000;

// Unchanged
NSInteger const kSyncManagerUnchanged = -1;

// soups and soup fields
NSString * const kSyncManagerLocal = @"__local__";
NSString * const kSyncManagerLocallyCreated = @"__locally_created__";
NSString * const kSyncManagerLocallyUpdated = @"__locally_updated__";
NSString * const kSyncManagerLocallyDeleted = @"__locally_deleted__";

static NSString * const kSFAppFeatureSmartSync   = @"SY";


// response
NSString * const kSyncManagerLObjectId = @"id"; // e.g. create response

// dispatch queue
char * const kSyncManagerQueue = "com.salesforce.smartsync.manager.syncmanager.QUEUE";

// block type
typedef void (^SyncUpdateBlock) (NSString* status, NSInteger progress, NSInteger totalSize, long long maxTimeStamp);
typedef void (^SyncFailBlock) (NSString* message, NSError* error);

@interface SFSmartSyncSyncManager () <SFAuthenticationManagerDelegate>

@property (nonatomic, strong) SFSmartStore *store;
@property (nonatomic, strong) dispatch_queue_t queue;
@property (nonatomic, strong) NSMutableSet *runningSyncIds;

@end


@implementation SFSmartSyncSyncManager

static NSMutableDictionary *syncMgrList = nil;

#pragma mark - instance access / cleanup

+ (void)initialize {
    if (self == [SFSmartSyncSyncManager class]) {
        syncMgrList = [NSMutableDictionary new];
    }
}

+ (instancetype)sharedInstance:(SFUserAccount *)user {
    return [self sharedInstanceForUser:user storeName:nil];
}

+ (instancetype)sharedInstanceForUser:(SFUserAccount *)user storeName:(NSString *)storeName {
    if (user == nil) return nil;
    if (storeName.length == 0) storeName = kDefaultSmartStoreName;
    
    SFSmartStore *store = [SFSmartStore sharedStoreWithName:storeName user:user];
    return [self sharedInstanceForStore:store];
}

+ (instancetype)sharedInstanceForStore:(SFSmartStore *)store {
    @synchronized ([SFSmartSyncSyncManager class]) {
        if (store == nil || store.storePath == nil) return nil;
        
        NSString *key = [SFSmartSyncSyncManager keyForStore:store];
        id syncMgr = [syncMgrList objectForKey:key];
        if (syncMgr == nil) {
            syncMgr = [[self alloc] initWithStore:store];
            syncMgrList[key] = syncMgr;
        }
        [[SalesforceSDKManager sharedManager] registerAppFeature:kSFAppFeatureSmartSync];
        return syncMgr;
    }
}

+ (void)removeSharedInstance:(SFUserAccount*)user {
    [self removeSharedInstanceForUser:user storeName:nil];
}

+ (void)removeSharedInstanceForUser:(SFUserAccount *)user storeName:(NSString *)storeName {
    if (user == nil) return;
    if (storeName.length == 0) storeName = kDefaultSmartStoreName;
    NSString* key = [SFSmartSyncSyncManager keyForUser:user storeName:storeName];
    [SFSmartSyncSyncManager removeSharedInstanceForKey:key];
}

+ (void)removeSharedInstanceForStore:(SFSmartStore*) store {
    NSString* key = [SFSmartSyncSyncManager keyForStore:store];
    [SFSmartSyncSyncManager removeSharedInstanceForKey:key];
}

+ (void)removeSharedInstanceForKey:(NSString*) key {
    @synchronized([SFSmartSyncSyncManager class]) {
        [syncMgrList removeObjectForKey:key];
    }
}

+ (void)removeSharedInstances {
    @synchronized (([SFSmartSyncSyncManager class])) {
        [syncMgrList removeAllObjects];
    }
}


+ (NSString*)keyForStore:(SFSmartStore*)store {
    return [SFSmartSyncSyncManager keyForUser:store.user storeName:store.storeName];
}

+ (NSString*)keyForUser:(SFUserAccount*)user storeName:(NSString*)storeName {
    NSString* keyPrefix = user == nil ? SFKeyForUserAndScope(nil, SFUserAccountScopeGlobal) : SFKeyForUserAndScope(user, SFUserAccountScopeCommunity);
    return [NSString  stringWithFormat:@"%@-%@", keyPrefix, storeName];
}



#pragma mark - init / dealloc

- (instancetype)initWithStore:(SFSmartStore *)store {
    self = [super init];
    if (self) {
        self.runningSyncIds = [NSMutableSet new];
        self.store = store;
        self.queue = dispatch_queue_create(kSyncManagerQueue,  DISPATCH_QUEUE_SERIAL);
        [[SFAuthenticationManager sharedManager] addDelegate:self];
        [SFSyncState setupSyncsSoupIfNeeded:self.store];
    }
    return self;
}



- (void)dealloc {
    [[SFAuthenticationManager sharedManager] removeDelegate:self];
}

#pragma mark - get sync / run sync methods

/** Return details about a sync
 @param syncId Sync ID.
 */
- (SFSyncState*)getSyncStatus:(NSNumber*)syncId {
    SFSyncState* sync = [SFSyncState newById:syncId store:self.store];
    
    if (sync == nil) {
        [self log:SFLogLevelError format:@"Sync %@ not found", syncId];
    }
    return sync;
}

/** Run a previously created sync
 */
- (void) runSync:(SFSyncState*) sync updateBlock:(SFSyncSyncManagerUpdateBlock)updateBlock {
    __weak typeof(self) weakSelf = self;
    SyncUpdateBlock updateSync = ^(NSString* status, NSInteger progress, NSInteger totalSize, long long maxTimeStamp) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (status == nil) status = (progress == 100 ? kSFSyncStateStatusDone : kSFSyncStateStatusRunning);
        sync.status = [SFSyncState syncStatusFromString:status];
        if (progress>=0)  sync.progress = progress;
        if (totalSize>=0) sync.totalSize = totalSize;
        if (maxTimeStamp>=0) sync.maxTimeStamp = (sync.maxTimeStamp < maxTimeStamp ? maxTimeStamp : sync.maxTimeStamp);
        [sync save:strongSelf.store];
        [strongSelf log:SFLogLevelDebug format:@"Sync update:%@", sync];
        NSString *eventName = nil;
        switch (sync.type) {
            case SFSyncStateSyncTypeDown:
                eventName = @"syncDown";
                break;
            case SFSyncStateSyncTypeUp:
                eventName = @"syncUp";
                break;
        }
        NSMutableDictionary *attributes = [[NSMutableDictionary alloc] init];
        attributes[@"numRecords"] = [NSNumber numberWithInteger:sync.totalSize];
        attributes[@"syncId"] = [NSNumber numberWithInteger:sync.syncId];
        attributes[@"syncTarget"] = NSStringFromClass([sync.target class]);
        switch (sync.status) {
            case SFSyncStateStatusNew:
                break; // should not happen
            case SFSyncStateStatusRunning:
                [strongSelf.runningSyncIds addObject:[NSNumber numberWithInteger:sync.syncId]];
                break;
            case SFSyncStateStatusDone:
            case SFSyncStateStatusFailed:
                [SFSDKEventBuilderHelper createAndStoreEvent:eventName userAccount:nil className:NSStringFromClass([self class]) attributes:attributes];
                [strongSelf.runningSyncIds removeObject:[NSNumber numberWithInteger:sync.syncId]];
                break;
        }
        if (updateBlock) {
            updateBlock(sync);
        }
    };

    SyncFailBlock failSync = ^(NSString* message, NSError* error) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        [strongSelf log:SFLogLevelError format:@"Sync type:%@ id:%d FAILED cause:%@ error:%@", [SFSyncState syncTypeToString:sync.type], sync.syncId, message, error];
        updateSync(kSFSyncStateStatusFailed, kSyncManagerUnchanged, kSyncManagerUnchanged, kSyncManagerUnchanged);
    };

    // Run on background thread
    updateSync(kSFSyncStateStatusRunning, 0, kSyncManagerUnchanged, kSyncManagerUnchanged);
    dispatch_async(self.queue, ^{
        __strong typeof(weakSelf) strongSelf = weakSelf;
        switch (sync.type) {
            case SFSyncStateSyncTypeDown:
                [strongSelf syncDown:sync updateSync:updateSync failSync:failSync];
                break;
            case SFSyncStateSyncTypeUp:
                [strongSelf syncUp:sync updateSync:updateSync failSync:failSync];
                break;
        }
    });
}

#pragma mark - syncDown, reSync and supporting methods

/** Create and run a sync down
 */
- (SFSyncState*) syncDownWithTarget:(SFSyncDownTarget*)target soupName:(NSString*)soupName updateBlock:(SFSyncSyncManagerUpdateBlock)updateBlock {
    SFSyncOptions* options = [SFSyncOptions newSyncOptionsForSyncDown:SFSyncStateMergeModeOverwrite];
    return [self syncDownWithTarget:target options:options soupName:soupName updateBlock:updateBlock];
}


/** Create and run a sync down
 */
- (SFSyncState*) syncDownWithTarget:(SFSyncDownTarget*)target options:(SFSyncOptions*)options soupName:(NSString*)soupName updateBlock:(SFSyncSyncManagerUpdateBlock)updateBlock {
    SFSyncState* sync = [SFSyncState newSyncDownWithOptions:options target:target soupName:soupName store:self.store];
    [self runSync:sync updateBlock:updateBlock];
    return [sync copy];
}

/** Resync
 */
- (SFSyncState*) reSync:(NSNumber*)syncId updateBlock:(SFSyncSyncManagerUpdateBlock)updateBlock {
    if ([self.runningSyncIds containsObject:syncId]) {
        [self log:SFLogLevelError format:@"Cannot run reSync:%@:still running", syncId];
        return nil;
    }
    SFSyncState* sync = [self getSyncStatus:(NSNumber *)syncId];
    if (sync == nil) {
        [self log:SFLogLevelError format:@"Cannot run reSync:%@:no sync found", syncId];
         return nil;
    }
    if (sync.type != SFSyncStateSyncTypeDown) {
        [self log:SFLogLevelError format:@"Cannot run reSync:%@:wrong type:%@", syncId, [SFSyncState syncTypeToString:sync.type]];
        return nil;
    }
    sync.totalSize = -1;
    [sync save:self.store];
    [self runSync:sync updateBlock:updateBlock];
    return [sync copy];
}


/** Run a sync down
 */
- (void) syncDown:(SFSyncState*)sync updateSync:(SyncUpdateBlock)updateSync failSync:(SyncFailBlock)failSync {
    NSString* soupName = sync.soupName;
    SFSyncStateMergeMode mergeMode = sync.mergeMode;
    SFSyncDownTarget* target = (SFSyncDownTarget*) sync.target;
    long long maxTimeStamp = sync.maxTimeStamp;

    SFSyncDownTargetFetchErrorBlock failBlock = ^(NSError *error) {
        failSync(@"Server call for sync down failed", error);
    };

    __block NSUInteger countFetched = 0;
    __block NSUInteger totalSize = 0;
    __block NSUInteger progress = 0;
    __block SFSyncDownTargetFetchCompleteBlock continueFetchBlockRecurse = ^(NSArray *records) {};
    __weak typeof(self) weakSelf = self;
    
    SFSyncDownTargetFetchCompleteBlock startFetchBlock = ^(NSArray* records) {
        totalSize = target.totalSize;
        updateSync(nil, totalSize == 0 ? 100 : 0, totalSize, kSyncManagerUnchanged);
        if (totalSize != 0) continueFetchBlockRecurse(records);
    };

    SFSyncDownTargetFetchCompleteBlock continueFetchBlock = ^(NSArray* records) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (records != nil) {
            countFetched += [records count];
            progress = 100*countFetched / totalSize;

            long long maxTimeStampForFetched = [target getLatestModificationTimeStamp:records];
            
            // Save records
            NSError *saveRecordsError = nil;
            [strongSelf saveRecords:records soup:soupName idFieldName:target.idFieldName mergeMode:mergeMode error:&saveRecordsError];
            if (saveRecordsError) {
                failSync(@"Failed to save SmartStore records on syncDown", saveRecordsError);
            } else {
                // Update status
                updateSync(nil, progress, totalSize, maxTimeStampForFetched);
                
                // Continue
                [target continueFetch:self errorBlock:failBlock completeBlock:continueFetchBlockRecurse];
            }
        }
        else {
            // In some cases (e.g. resync for refresh sync down), the totalSize is just an (over)estimation
            // As a result progress might not get to 100 and therefore a DONE would never be sent
            if (progress < 100) {
                updateSync(nil, 100, -1 /*unchanged*/, -1 /*unchanged*/);
            }
        }
    };
    
    // initialize the alias
    continueFetchBlockRecurse = continueFetchBlock;
    
    // Start fetch
    [target startFetch:self maxTimeStamp:maxTimeStamp errorBlock:failBlock completeBlock:startFetchBlock];
}

- (void) saveRecords:(NSArray*)records
                soup:(NSString*)soupName
         idFieldName:(NSString *)idFieldName
           mergeMode:(SFSyncStateMergeMode)mergeMode
               error:(NSError **)error {
    NSMutableArray* recordsToSave = [NSMutableArray array];
    
    NSOrderedSet* idsToSkip = nil;
    if (mergeMode == SFSyncStateMergeModeLeaveIfChanged) {
        idsToSkip = [self getDirtyRecordIds:soupName idField:idFieldName];
    }
    
    // Prepare for smartstore
    for (NSDictionary* record in records) {
        // Skip?
        if (idsToSkip != nil && [idsToSkip containsObject:record[idFieldName]]) {
            continue;
        }
        
        NSMutableDictionary* udpatedRecord = [record mutableCopy];
        udpatedRecord[kSyncManagerLocal] = @NO;
        udpatedRecord[kSyncManagerLocallyCreated] = @NO;
        udpatedRecord[kSyncManagerLocallyUpdated] = @NO;
        udpatedRecord[kSyncManagerLocallyDeleted] = @NO;
        [recordsToSave addObject:udpatedRecord];
    }
    
    // Save to smartstore
    NSError *upsertError = nil;
    [self.store upsertEntries:recordsToSave toSoup:soupName withExternalIdPath:idFieldName error:&upsertError];
    if (upsertError && error) {
        *error = upsertError;
    }
}

- (NSOrderedSet*) getDirtyRecordIds:(NSString*)soupName idField:(NSString*)idField {
    NSMutableOrderedSet* ids = [NSMutableOrderedSet new];
    
    NSString* dirtyRecordSql = [NSString stringWithFormat:@"SELECT {%@:%@} FROM {%@} WHERE {%@:%@} = '1' ORDER BY {%@:%@} ASC", soupName, idField, soupName, soupName, kSyncManagerLocal, soupName, idField];
    SFQuerySpec* querySpec = [SFQuerySpec newSmartQuerySpec:dirtyRecordSql withPageSize:kSyncManagerPageSize];

    BOOL hasMore = YES;
    for (NSUInteger pageIndex=0; hasMore; pageIndex++) {
        NSArray* results = [self.store queryWithQuerySpec:querySpec pageIndex:pageIndex error:nil];
        hasMore = (results.count == kSyncManagerPageSize);
        [ids addObjectsFromArray:[self flatten:results]];
    }
    return ids;
}

- (NSArray*) flatten:(NSArray*)results {
    NSMutableArray* flatArray = [NSMutableArray new];
    for (NSArray* row in results) {
        [flatArray addObjectsFromArray:row];
    }
    return flatArray;
}

#pragma mark - syncUp and supporting methods

/** Create and run a sync up
 */
- (SFSyncState*) syncUpWithOptions:(SFSyncOptions*)options soupName:(NSString*)soupName updateBlock:(SFSyncSyncManagerUpdateBlock)updateBlock {
    SFSyncState *sync = [SFSyncState newSyncUpWithOptions:options soupName:soupName store:self.store];
    [self runSync:sync updateBlock:updateBlock];
    return [sync copy];
}

- (SFSyncState*)syncUpWithTarget:(SFSyncUpTarget *)target
                         options:(SFSyncOptions *)options
                        soupName:(NSString *)soupName
                     updateBlock:(SFSyncSyncManagerUpdateBlock)updateBlock {
    SFSyncState *sync = [SFSyncState newSyncUpWithOptions:options target:target soupName:soupName store:self.store];
    [self runSync:sync updateBlock:updateBlock];
    return [sync copy];
}

/** Run a sync up
 */
- (void) syncUp:(SFSyncState*)sync updateSync:(SyncUpdateBlock)updateSync failSync:(SyncFailBlock)failSync {
    NSString* soupName = sync.soupName;
    SFSyncUpTarget* target = (SFSyncUpTarget*) sync.target;

    // Call smartstore
    NSArray* dirtyRecordIds = [target getIdsOfRecordsToSyncUp:self soupName:soupName];
    NSUInteger totalSize = [dirtyRecordIds count];
    if (totalSize == 0) {
        updateSync(nil, 100, totalSize, kSyncManagerUnchanged);
        return;
    }
    
    // Fail block for rest call
    SFSyncUpTargetErrorBlock failBlock = ^(NSError *error) {
        failSync(@"Server call for sync up failed", error);
    };

    // Otherwise, there's work to do.
    [self syncUpOneEntry:sync recordIds:dirtyRecordIds index:0 updateSync:updateSync failBlock:failBlock];
}

- (void) cleanResyncGhosts:(NSNumber*)syncId completionStatusBlock:(SFSyncSyncManagerCompletionStatusBlock)completionStatusBlock {
    if ([self.runningSyncIds containsObject:syncId]) {
        [self log:SFLogLevelError format:@"Cannot run cleanResyncGhosts:%@:still running", syncId];
        return;
    }
    SFSyncState* sync = [self getSyncStatus:(NSNumber *)syncId];
    if (sync == nil) {
        [self log:SFLogLevelError format:@"Cannot run cleanResyncGhosts:%@:no sync found", syncId];
        return;
    }
    if (sync.type != SFSyncStateSyncTypeDown) {
        [self log:SFLogLevelError format:@"Cannot run cleanResyncGhosts:%@:wrong type:%@", syncId, [SFSyncState syncTypeToString:sync.type]];
        return;
    }
    NSString* soupName = [sync soupName];
    NSString* idFieldName = [sync.target idFieldName];

    /*
     * Fetches list of IDs present in local soup that have not been modified locally.
     */
    SFQuerySpec* querySpec = [SFQuerySpec newAllQuerySpec:soupName withOrderPath:idFieldName withOrder:kSFSoupQuerySortOrderAscending withPageSize:10];
    NSUInteger count = [self.store countWithQuerySpec:querySpec error:nil];
    NSMutableString* smartSqlQuery = [[NSMutableString alloc] init];
    [smartSqlQuery appendString:@"SELECT {"];
    [smartSqlQuery appendString:soupName];
    [smartSqlQuery appendString:@":"];
    [smartSqlQuery appendString:idFieldName];
    [smartSqlQuery appendString:@"} FROM {"];
    [smartSqlQuery appendString:soupName];
    [smartSqlQuery appendString:@"} WHERE {"];
    [smartSqlQuery appendString:soupName];
    [smartSqlQuery appendString:@":"];
    [smartSqlQuery appendString:kSyncManagerLocal];
    [smartSqlQuery appendString:@"}='0'"];
    querySpec = [SFQuerySpec newSmartQuerySpec:smartSqlQuery withPageSize:count];
    __block NSMutableArray* localIds = [[NSMutableArray alloc] init];
    NSArray* rows = [self.store queryWithQuerySpec:querySpec pageIndex:0 error:nil];
    for (NSArray* row in rows) {
        [localIds addObject:row[0]];
    }

    /*
     * Fetches list of IDs still present on the server from the list of local IDs
     * and removes the list of IDs that are still present on the server.
     */
    __weak typeof(self) weakSelf = self;
    __block NSMutableArray* remoteIds = [[NSMutableArray alloc] init];
    [((SFSyncDownTarget*) sync.target) getListOfRemoteIds:self localIds:localIds errorBlock:^(NSError* e) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        [strongSelf log:SFLogLevelError format:@"Failed to get list of remote IDs, %@", [e localizedDescription]];
        NSMutableDictionary *attributes = [[NSMutableDictionary alloc] init];
        attributes[@"syncId"] = [NSNumber numberWithInteger:sync.syncId];
        attributes[@"syncTarget"] = NSStringFromClass([sync.target class]);
        [SFSDKEventBuilderHelper createAndStoreEvent:@"cleanResyncGhosts" userAccount:nil className:NSStringFromClass([self class]) attributes:attributes];
        completionStatusBlock(SFSyncStateStatusFailed);
    } completeBlock:^(NSArray* records) {
        __strong typeof(weakSelf) strongSelf = weakSelf;
        if (records != nil) {
            for (NSDictionary* record in records) {
                if (record != nil) {
                    NSString *id = record[idFieldName];
                    [remoteIds addObject:id];
                }
            }
            [localIds removeObjectsInArray:remoteIds];
            // Deletes extra IDs from SmartStore.
            if (localIds.count > 0) {
                NSString* smartSql = [NSString stringWithFormat:@"SELECT {%@:%@} FROM {%@} WHERE {%@:%@} IN ('%@')", soupName, SOUP_ENTRY_ID, soupName, soupName, idFieldName, [localIds componentsJoinedByString:@", "]];
                SFQuerySpec* querySpec = [SFQuerySpec newSmartQuerySpec:smartSql withPageSize:localIds.count];
                [strongSelf.store removeEntriesByQuery:querySpec fromSoup:soupName];
            }
        }
        NSMutableDictionary *attributes = [[NSMutableDictionary alloc] init];
        attributes[@"numRecords"] = [NSNumber numberWithInteger:localIds.count];
        attributes[@"syncId"] = [NSNumber numberWithInteger:sync.syncId];
        attributes[@"syncTarget"] = NSStringFromClass([sync.target class]);
        [SFSDKEventBuilderHelper createAndStoreEvent:@"cleanResyncGhosts" userAccount:nil className:NSStringFromClass([self class]) attributes:attributes];
        completionStatusBlock(SFSyncStateStatusDone);
    }];
}

- (void)syncUpOneEntry:(SFSyncState*)sync
             recordIds:(NSArray*)recordIds
                 index:(NSUInteger)i
            updateSync:(SyncUpdateBlock)updateSync
             failBlock:(SFSyncUpTargetErrorBlock)failBlock {
    SFSyncUpTarget *target = (SFSyncUpTarget *)sync.target;
    NSString* soupName = sync.soupName;
    SFSyncStateMergeMode mergeMode = sync.mergeMode;
    NSUInteger totalSize = recordIds.count;
    NSUInteger progress = i*100 / totalSize;
    updateSync(nil, progress, totalSize, kSyncManagerUnchanged);
    
    if (progress == 100) {
        // Done
        return;
    }
    
    NSString* idStr = [(NSNumber*) recordIds[i] stringValue];
    NSMutableDictionary* record = [[self.store retrieveEntries:@[idStr] fromSoup:soupName][0] mutableCopy];
    
    // Do we need to do a create, update or delete
    BOOL locallyCreated = [record[kSyncManagerLocallyCreated] boolValue];
    BOOL locallyUpdated = [record[kSyncManagerLocallyUpdated] boolValue];
    BOOL locallyDeleted = [record[kSyncManagerLocallyDeleted] boolValue];
    
    SFSyncUpTargetAction action = SFSyncUpTargetActionNone;
    if (locallyDeleted)
        action = SFSyncUpTargetActionDelete;
    else if (locallyCreated)
        action = SFSyncUpTargetActionCreate;
    else if (locallyUpdated)
        action = SFSyncUpTargetActionUpdate;
    
    if (action == SFSyncUpTargetActionNone) {
        // Next
        [self syncUpOneEntry:sync recordIds:recordIds index:i+1 updateSync:updateSync failBlock:failBlock];
        return;
    }
    
    /*
     * Checks if we are attempting to update a record that has been updated
     * on the server AFTER the client's last sync down. If the merge mode
     * passed in tells us to leave the record alone under these
     * circumstances, we will do nothing and return here.
     */
    if (mergeMode == SFSyncStateMergeModeLeaveIfChanged && !locallyCreated) {
        // Need to check the modification date on the server, against the local date.
        __weak typeof(self) weakSelf = self;
        SFSyncUpRecordModificationResultBlock modificationBlock = ^(NSDate *localDate, NSDate *serverDate, NSError *error) {
            __strong typeof(weakSelf) strongSelf = weakSelf;
            if (localDate == nil // We didn't capture the last modified date so we can't really enforce merge mode
                || serverDate == nil // We were unable to get the last modified date from the server
                || [localDate compare:serverDate] != NSOrderedAscending) // local date is newer than server
            {
                [strongSelf resumeSyncUpOneEntry:sync
                                       recordIds:recordIds
                                           index:i
                                          record:record
                                          action:action
                                      updateSync:updateSync
                                       failBlock:failBlock];
            } else {
                // Server date is newer than the local date.  Skip this update.
                [strongSelf log:SFLogLevelInfo format:@"Record with id '%@' has been modified on the server.  Local last mod date: %@, Server last mod date: %@ . Skipping.", record[target.idFieldName], localDate, serverDate];
                [strongSelf syncUpOneEntry:sync
                                 recordIds:recordIds
                                     index:i+1
                                updateSync:updateSync
                                 failBlock:failBlock];
            }
        };
        
        [target fetchRecordModificationDates:record modificationResultBlock:modificationBlock];
    } else {
        // State is such that we can simply update the record directly.
        [self resumeSyncUpOneEntry:sync recordIds:recordIds index:i record:record action:action updateSync:updateSync failBlock:failBlock];
    }
}

- (void)resumeSyncUpOneEntry:(SFSyncState*)sync
                   recordIds:(NSArray*)recordIds
                       index:(NSUInteger)i
                      record:(NSMutableDictionary*)record
                      action:(SFSyncUpTargetAction)action
                  updateSync:(SyncUpdateBlock)updateSync
                   failBlock:(SFSyncUpTargetErrorBlock)failBlock {
    
    SFSyncStateMergeMode mergeMode = sync.mergeMode;
    SFSyncUpTarget *target = (SFSyncUpTarget *)sync.target;
    NSString* soupName = sync.soupName;
    NSNumber* soupEntryId = record[SOUP_ENTRY_ID];
    
    // Getting type and id
    NSString* objectType = [SFJsonUtils projectIntoJson:record path:kObjectTypeField];
    NSString* objectId = record[target.idFieldName];

    // Fields to save (in the case of create or update)
    NSMutableDictionary* fields = [NSMutableDictionary dictionary];
    if (action == SFSyncUpTargetActionCreate || action == SFSyncUpTargetActionUpdate) {
        NSArray *fieldList;
        // During create use options.createFieldlist if specified
        if (action == SFSyncUpTargetActionCreate && sync.options.createFieldlist) {
            fieldList = sync.options.createFieldlist;
        }
        // During update use options.updateFieldlist if specified
        else if (action == SFSyncUpTargetActionUpdate && sync.options.updateFieldlist) {
            fieldList = sync.options.updateFieldlist;
        }
        // Otherwise use options.fieldlist
        else {
            fieldList = sync.options.fieldlist;
        }

        for (NSString *fieldName in fieldList) {
            if (![fieldName isEqualToString:target.idFieldName] && ![fieldName isEqualToString:target.modificationDateFieldName]) {
                NSObject* fieldValue = [SFJsonUtils projectIntoJson:record path:fieldName];
                if (fieldValue != nil)
                    fields[fieldName] = fieldValue;
            }
        }
    }
    
    // Delete handler
    SFSyncUpTargetCompleteBlock completeBlockDelete = ^(NSDictionary *d) {
        // Remove entry on delete
        [self.store removeEntries:@[soupEntryId] fromSoup:soupName];
        
        // Next
        [self syncUpOneEntry:sync recordIds:recordIds index:i+1 updateSync:updateSync failBlock:failBlock];
    };
    
    // Update handler
    SFSyncUpTargetCompleteBlock completeBlockUpdate = ^(NSDictionary *d) {
        // Set local flags to false
        record[kSyncManagerLocal] = @NO;
        record[kSyncManagerLocallyCreated] = @NO;
        record[kSyncManagerLocallyUpdated] = @NO;
        record[kSyncManagerLocallyDeleted] = @NO;
        
        // Update smartstore
        [self.store upsertEntries:@[record] toSoup:soupName];
        
        // Next
        [self syncUpOneEntry:sync recordIds:recordIds index:i+1 updateSync:updateSync failBlock:failBlock];
    };
    
    // Create handler
    SFSyncUpTargetCompleteBlock completeBlockCreate = ^(NSDictionary *d) {
        // Replace id with server id during create
        record[target.idFieldName] = d[kSyncManagerLObjectId];
        completeBlockUpdate(d);
    };
    
    // Update failure handler
    SFSyncUpTargetErrorBlock failBlockUpdate = ^ (NSError* err){
        // Handling remotely deleted records
        if (err.code == 404) {
            if (mergeMode == SFSyncStateMergeModeOverwrite) {
                [target createOnServer:objectType fields:fields completionBlock:completeBlockCreate failBlock:failBlock];
            }
            else {
                // Next
                [self syncUpOneEntry:sync recordIds:recordIds index:i+1 updateSync:updateSync failBlock:failBlock];
            }
        }
        else {
            failBlock(err);
        }
    };
    
    // Delete failure handler
    SFSyncUpTargetErrorBlock failBlockDelete = ^ (NSError* err){
        // Handling remotely deleted records
        if (err.code == 404) {
            completeBlockDelete(nil);
        }
        else {
            failBlock(err);
        }
    };
    
    switch(action) {
        case SFSyncUpTargetActionCreate:
            [target createOnServer:objectType fields:fields completionBlock:completeBlockCreate failBlock:failBlock];
            break;
        case SFSyncUpTargetActionUpdate:
            [target updateOnServer:objectType objectId:objectId fields:fields completionBlock:completeBlockUpdate failBlock:failBlockUpdate];
            break;
        case SFSyncUpTargetActionDelete:
            [target deleteOnServer:objectType objectId:objectId completionBlock:completeBlockDelete failBlock:failBlockDelete];
            break;
        default:
            // Action is unsupported here.  Move on.
            [self log:SFLogLevelInfo format:@"%@ unsupported action with value %d.  Moving to the next record.", NSStringFromSelector(_cmd), action];
            [self syncUpOneEntry:sync recordIds:recordIds index:i+1 updateSync:updateSync failBlock:failBlock];
            return;
    }
}

#pragma mark - SFAuthenticationManagerDelegate

- (void)authManager:(SFAuthenticationManager *)manager willLogoutUser:(SFUserAccount *)user {
    [[self class] removeSharedInstance:user];
}

@end
