/*
 SalesforceSDKManagerExtensions
 Created by Raj Rao on 11/27/17.
 
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
import Foundation
import SalesforceSDKCore
import PromiseKit

extension SalesforceSDKManager {
    
    static var Builder = SalesforceSDKManagerBuilder.self
    
    class func configure(config : @escaping (SFSDKAppConfig) -> Void ) -> SalesforceSDKManager.Type  {
        config(SalesforceSDKManager.shared().appConfig!)
        return SalesforceSDKManager.self
    }
    
    
    class SalesforceSDKManagerBuilder {
        /**
         Provides a Builder based mechanism to setup the app config for the Salesforce Application.
         ```
         SalesforceSDKManager.Builder.configure { (appconfig) in
             appconfig.remoteAccessConsumerKey = RemoteAccessConsumerKey
             appconfig.oauthRedirectURI = OAuthRedirectURI
             appconfig.oauthScopes = ["web", "api"]
         }
         ```
         - Parameter config: The block which will be invoked with a config object.
         - Returns: The instance of SalesforceSDKManagerBuilder.
         */
        class func configure(config : @escaping (SFSDKAppConfig) -> Void ) -> SalesforceSDKManagerBuilder.Type {
            config(SalesforceSDKManager.shared().appConfig!)
            return SalesforceSDKManagerBuilder.self
        }

        /**
         Provides a way to set the post launch action for the Salesforce Application.
         ```
         SalesforceSDKManager.Builder.configure { (appconfig) in
             appconfig.remoteAccessConsumerKey = RemoteAccessConsumerKey
             appconfig.oauthRedirectURI = OAuthRedirectURI
             appconfig.oauthScopes = ["web", "api"]
         }
         .postLaunch {  [unowned self] (launchActionList: SFSDKLaunchAction) in
             let launchActionString = SalesforceSDKManager.launchActionsStringRepresentation(launchActionList)
             SalesforceSwiftLogger.log(type(of:self), level:.info, message:"Post-launch: launch actions taken: \(launchActionString)")
         }.done()
         ```
         - Parameter action: The block which will be invoked after a succesfull SDK Launch.
         - Returns: The instance of SalesforceSDKManagerBuilder.
         */
        class func postLaunch(action : @escaping SFSDKPostLaunchCallbackBlock) -> SalesforceSDKManagerBuilder.Type {
            SalesforceSDKManager.shared().postLaunchAction = action
            return SalesforceSDKManagerBuilder.self
        }

        /**
         Provides a way to set the post logout action for the Salesforce Application.
         ```
         SalesforceSDKManager.Builder.configure { (appconfig) in
             appconfig.remoteAccessConsumerKey = RemoteAccessConsumerKey
             appconfig.oauthRedirectURI = OAuthRedirectURI
             appconfig.oauthScopes = ["web", "api"]
         }
         .postLaunch {  (launchActionList: SFSDKLaunchAction) in
            ...
         }
         .postLogout {
             
         }.done()
         ```
         - Parameter action: The block which will be invoked after a succesfull SDK Launch.
         - Returns: The instance of SalesforceSDKManagerBuilder.
         */
        class func postLogout(action : @escaping SFSDKLogoutCallbackBlock) -> SalesforceSDKManagerBuilder.Type {
            SalesforceSDKManager.shared().postLogoutAction = action
            return SalesforceSDKManagerBuilder.self
        }
        /**
         Provides a way to set the switch user action for the Salesforce Application.
         ```
         SalesforceSDKManager.Builder.configure { (appconfig) in
         appconfig.remoteAccessConsumerKey = RemoteAccessConsumerKey
         appconfig.oauthRedirectURI = OAuthRedirectURI
         appconfig.oauthScopes = ["web", "api"]
         }
         .postLaunch {  (launchActionList: SFSDKLaunchAction) in
         ...
         }
         .postLogout {
         
         }
         .switchUser { from,to in
         
         }.done()
         ```
         - Parameter action: The block which will be invoked after a succesfull SDK Launch.
         - Returns: The instance of SalesforceSDKManagerBuilder.
         */
        
        class func switchUser(action : @escaping SFSDKSwitchUserCallbackBlock) -> SalesforceSDKManagerBuilder.Type {
            SalesforceSDKManager.shared().switchUserAction = action
            return SalesforceSDKManagerBuilder.self
        }

        /**
         Provides a way to set the error handling during sdk launch for the Salesforce Application.
         ```
         SalesforceSDKManager.Builder.configure { (appconfig) in
             appconfig.remoteAccessConsumerKey = RemoteAccessConsumerKey
             appconfig.oauthRedirectURI = OAuthRedirectURI
             appconfig.oauthScopes = ["web", "api"]
         }
         .postLaunch {  (launchActionList: SFSDKLaunchAction) in
         ...
         }
         .postLogout {
         
         }
         .switchUser { from,to in
         
         }
         .launchError { error,launchAction in
         
         }.done()
         ```
         - Parameter action: The block which will be invoked after a succesfull SDK Launch.
         - Returns: The instance of SalesforceSDKManagerBuilder.
         */
        class func launchError(action : @escaping SFSDKLaunchErrorCallbackBlock) -> SalesforceSDKManagerBuilder.Type {
            SalesforceSDKManager.shared().launchErrorAction = action
            SalesforceSwiftLogger.d(SalesforceSDKManager.self, message: "error")
            return SalesforceSDKManagerBuilder.self
        }
        
        /**
         Last call for the builder returns Void to suppress warnings.
        */
        class func done () -> Void {
            
        }
    }
    
}

