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

#import "SFSmartSyncPlugin.h"
#import "CDVPlugin+SFAdditions.h"
#import <SalesforceSDKCore/NSDictionary+SFAdditions.h>
#import <SmartStore/SFSmartStore.h>
#import <SmartSync/SFSmartSyncSyncManager.h>

// NOTE: must match value in Cordova's config.xml file.
NSString * const kSmartSyncPluginIdentifier = @"com.salesforce.smartsync";

// Private constants.
NSString *const kSyncSoupNameArg = @"soupName";
NSString *const kSyncTargetArg = @"target";
NSString *const kSyncOptionsArg = @"options";
NSString *const kSyncIdArg = @"syncId";
NSString *const kSyncNameArg = @"syncName";
NSString *const kSyncEventType = @"sync";
NSString *const kSyncDetail = @"detail";
NSString *const kSyncIsGlobalStoreArg = @"isGlobalStore";
NSString *const kSyncStoreNameArg = @"storeName";

@implementation SFSmartSyncPlugin

- (void) resetSyncManager
{
    [SFSmartSyncSyncManager removeSharedInstances];
}

- (void) handleSyncUpdate:(SFSyncState*)sync withArgs:(NSDictionary *)args
{
    dispatch_async(dispatch_get_main_queue(), ^{
        NSError *error = nil;
        if ([NSJSONSerialization isValidJSONObject:[sync asDict]]) {
            NSMutableDictionary* detailDict = [NSMutableDictionary dictionaryWithDictionary:[sync asDict]];
            detailDict[kSyncIsGlobalStoreArg] = [self isGlobal:args]?@YES:@NO;
            detailDict[kSyncStoreNameArg] = [self storeName:args];
            NSData *detailData = [NSJSONSerialization dataWithJSONObject:detailDict
                                                                 options:0 // non-pretty printing
                                                                   error:&error];
            if (error) {
                [SFSDKHybridLogger e:[self class] format:@"JSON Parsing Error: %@", error];
            } else {
                NSString* detailAsString = [[NSString alloc] initWithData:detailData encoding:NSUTF8StringEncoding];
                NSString* js = [
                                @[@"document.dispatchEvent(new CustomEvent(\"",
                                  kSyncEventType,
                                  @"\", { \"",
                                  kSyncDetail,
                                  @"\": ",
                                  detailAsString,
                                  @"}))" ]
                                componentsJoinedByString:@""
                                ];
                [self.commandDelegate evalJs:js];
            }
        } else {
            [SFSDKHybridLogger d:[self class] format:@"Invalid object passed to JSONDataRepresentation???"];
        }
    });
}

#pragma mark - Smart sync plugin methods

- (void) getSyncStatus:(CDVInvokedUrlCommand *)command
{
    [self runCommand:^(NSDictionary* argsDict) {
        NSNumber *syncId = (NSNumber *) [argsDict nonNullObjectForKey:kSyncIdArg];
        NSString *syncName = (NSString *) [argsDict nonNullObjectForKey:kSyncNameArg];

        SFSyncState *sync;
        if (syncId) {
            [SFSDKHybridLogger d:[self class] format:@"getSyncStatus with sync id: %@", syncId];
            sync = [[self getSyncManagerInst:argsDict] getSyncStatus:syncId];
        }
        else if (syncName) {
            [SFSDKHybridLogger d:[self class] format:@"getSyncStatus with sync name: %@", syncName];
            sync = [[self getSyncManagerInst:argsDict] getSyncStatusByName:syncName];
        }
        else {
            NSString *errorMessage = @"Neither syncId nor syncName were specified";
            return [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:errorMessage];
        }

        // cordova can't return null, so returning {} when sync is not found
        // cordova.force.js turns it back into a null
        return [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:(sync?[sync asDict]:@{})];

    } command:command];
}

- (void) deleteSync:(CDVInvokedUrlCommand *)command
{
    [self runCommand:^(NSDictionary* argsDict) {
        NSNumber *syncId = (NSNumber *) [argsDict nonNullObjectForKey:kSyncIdArg];
        NSString *syncName = (NSString *) [argsDict nonNullObjectForKey:kSyncNameArg];

        if (syncId) {
            [SFSDKHybridLogger d:[self class] format:@"getSyncStatus with sync id: %@", syncId];
            [[self getSyncManagerInst:argsDict] deleteSyncById:syncId];
        }
        else if (syncName) {
            [SFSDKHybridLogger d:[self class] format:@"getSyncStatus with sync name: %@", syncName];
            [[self getSyncManagerInst:argsDict] deleteSyncByName:syncName];
        }
        else {
            NSString *errorMessage = @"Neither syncId nor syncName were specified";
            return [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:errorMessage];
        }

        return [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];

    } command:command];
}

- (void) syncDown:(CDVInvokedUrlCommand *)command
{
    [self runCommand:^(NSDictionary* argsDict) {
        NSString *syncName = [argsDict nonNullObjectForKey:kSyncNameArg];
        NSString *soupName = [argsDict nonNullObjectForKey:kSyncSoupNameArg];
        SFSyncOptions *options = [SFSyncOptions newFromDict:[argsDict nonNullObjectForKey:kSyncOptionsArg]];
        SFSyncDownTarget *target = [SFSyncDownTarget newFromDict:[argsDict nonNullObjectForKey:kSyncTargetArg]];
        __weak typeof(self) weakSelf = self;
        SFSyncState* sync = [[self getSyncManagerInst:argsDict] syncDownWithTarget:target options:options soupName:soupName syncName:syncName updateBlock:^(SFSyncState* sync) {
            [weakSelf handleSyncUpdate:sync withArgs:argsDict];
        }];
        [SFSDKHybridLogger d:[self class] format:@"syncDown # %ld from soup: %@", sync.syncId, soupName];
        return [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:[sync asDict]];
    } command:command];
}

- (void) reSync:(CDVInvokedUrlCommand *)command
{
    [self runCommand:^(NSDictionary* argsDict) {
        NSNumber *syncId = (NSNumber *) [argsDict nonNullObjectForKey:kSyncIdArg];
        NSString *syncName = (NSString *) [argsDict nonNullObjectForKey:kSyncNameArg];

        SFSyncState *sync;
        if (syncId) {
            [SFSDKHybridLogger d:[self class] format:@"reSync with sync id: %@", syncId];
            __weak typeof(self) weakSelf = self;
            sync = [[self getSyncManagerInst:argsDict] reSync:syncId updateBlock:^(SFSyncState* sync) {
                [weakSelf handleSyncUpdate:sync withArgs:argsDict];
            }];
        } else if (syncName) {
            [SFSDKHybridLogger d:[self class] format:@"reSync with sync name: %@", syncName];
            __weak typeof(self) weakSelf = self;
            sync = [[self getSyncManagerInst:argsDict] reSyncByName:syncName updateBlock:^(SFSyncState* sync) {
                [weakSelf handleSyncUpdate:sync withArgs:argsDict];
            }];
        } else {
            NSString *errorMessage = @"Neither syncId nor syncName were specified";
            return [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:errorMessage];
        }

        if (sync) {
            return [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:[sync asDict]];
        } else {
            return [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
        }
    } command:command];
}

- (void) cleanResyncGhosts:(CDVInvokedUrlCommand *)command
{
    NSDictionary *argsDict = [self getArgument:command.arguments atIndex:0];
    NSNumber* syncId = (NSNumber*) [argsDict nonNullObjectForKey:kSyncIdArg];
    [SFSDKHybridLogger d:[self class] format:@"cleanResyncGhosts with sync id: %@", syncId];
    id <CDVCommandDelegate> commandDelegate = self.commandDelegate;
    NSString* callbackId = command.callbackId;
    [[self getSyncManagerInst:argsDict] cleanResyncGhosts:syncId completionStatusBlock:^(SFSyncStateStatus syncStatus) {
        CDVPluginResult* pluginResult;
        if (syncStatus == SFSyncStateStatusDone) {
            [SFSDKHybridLogger d:[self class] format:@"cleanResyncGhosts completed successfully"];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        } else {
            [SFSDKHybridLogger e:[self class] format:@"cleanResyncGhosts did not complete successfully"];
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
        }
        [commandDelegate sendPluginResult:pluginResult callbackId:callbackId];
    }];
}

- (void) syncUp:(CDVInvokedUrlCommand *)command
{
    [self runCommand:^(NSDictionary* argsDict) {
        NSString *syncName = [argsDict nonNullObjectForKey:kSyncNameArg];
        NSString *soupName = [argsDict nonNullObjectForKey:kSyncSoupNameArg];
        SFSyncOptions *options = [SFSyncOptions newFromDict:[argsDict nonNullObjectForKey:kSyncOptionsArg]];
        SFSyncUpTarget *target = [SFSyncUpTarget newFromDict:[argsDict nonNullObjectForKey:kSyncTargetArg]];
        __weak typeof(self) weakSelf = self;
        SFSyncState* sync = [[self getSyncManagerInst:argsDict] syncUpWithTarget:target options:options soupName:soupName syncName:syncName updateBlock:^(SFSyncState* sync) {
            [weakSelf handleSyncUpdate:sync withArgs:argsDict];
        }];
        [SFSDKHybridLogger d:[self class] format:@"syncUp # %ld from soup: %@", sync.syncId, soupName];
        return [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:[sync asDict]];
    } command:command];
}

- (SFSmartStore *)storeWithName:(NSString *)storeName isGlobal:(BOOL) isGlobal
{
    SFSmartStore *store = isGlobal?[SFSmartStore sharedGlobalStoreWithName:storeName]:
                                   [SFSmartStore sharedStoreWithName:storeName];
    return store;
}

- (SFSmartSyncSyncManager *)getSyncManagerInst:(NSDictionary *)args
{
    NSString *storeName = [self storeName:args];
    BOOL isGlobal = [self isGlobal:args];
    SFSmartStore *storeInst = [self storeWithName:storeName isGlobal:isGlobal];
    return [SFSmartSyncSyncManager sharedInstanceForStore:storeInst];
}

- (NSString *)storeName:(NSDictionary *)args
{
    NSString *storeName = [args nonNullObjectForKey:kSyncStoreNameArg];
    if(storeName==nil) {
        storeName = kDefaultSmartStoreName;
    }
    return storeName;
}

- (BOOL) isGlobal:(NSDictionary *)args
{
    return args[kSyncIsGlobalStoreArg] != nil && [args[kSyncIsGlobalStoreArg] boolValue];
}

@end
