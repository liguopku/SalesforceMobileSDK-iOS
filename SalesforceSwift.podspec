Pod::Spec.new do |s|

  s.name         = "SalesforceSwift"
  s.version      = "6.0.0"
  s.summary      = "Salesforce Mobile SDK for iOS - Swift"
  s.homepage     = "https://github.com/forcedotcom/SalesforceMobileSDK-iOS"

  s.license      = { :type => "Salesforce.com Mobile SDK License", :file => "LICENSE.md" }
  s.author       = { "Raj Rao" => "rao.r@salesforce.com" }

  s.platform     = :ios, "10.0"

  s.source       = { :git => "https://github.com/forcedotcom/SalesforceMobileSDK-iOS.git",
                     :tag => "v#{s.version}",
                     :submodules => true }

  s.requires_arc = true
  s.default_subspec  = 'SalesforceSwift'

  s.subspec 'SalesforceSwift' do |salesforceswift|

      salesforceswift.dependency 'SmartSync'
      salesforceswift.source_files = 'libs/SalesforceSwiftSDK/SalesforceSwiftSDK/**/*.{h,m,swift}'
      salesforceswift.public_header_files = 'libs/SalesforceSwiftSDK/SalesforceSwiftSDK/SalesforceSwiftSDK.h'
      salesforceswift.prefix_header_contents = '#import "SFSDKSmartSyncLogger.h"'
      salesforceswift.requires_arc = true

  end

end
