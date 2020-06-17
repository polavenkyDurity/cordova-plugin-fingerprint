//
//  Fingerprint.swift
//  keychain-sample
//
//  Created by Ashima Sharma on 6/15/20.
//  Copyright © 2020 Alexei Gridnev. All rights reserved.
//

import Foundation
import LocalAuthentication


@objc(fingerprint) class fingerprint : CDVPlugin {

    enum PluginError:Int {
        case BIOMETRIC_UNKNOWN_ERROR = -100
        case BIOMETRIC_UNAVAILABLE = -101
        case BIOMETRIC_AUTHENTICATION_FAILED = -102
        case BIOMETRIC_PERMISSION_NOT_GRANTED = -105
        case BIOMETRIC_NOT_ENROLLED = -106
        case BIOMETRIC_DISMISSED = -108
        case BIOMETRIC_SCREEN_GUARD_UNSECURED = -110
        case BIOMETRIC_LOCKED_OUT = -111
    }

    struct ErrorCodes {
        var code: Int
    }


    @objc(isAvailable:)
    func isAvailable(_ command: CDVInvokedUrlCommand){
        let authenticationContext = LAContext();
        var biometryType = "finger";
        var errorResponse: [AnyHashable: Any] = [
            "code": 0,
            "message": "Not Available"
        ];
        var error:NSError?;
        let policy:LAPolicy = .deviceOwnerAuthenticationWithBiometrics;
        var pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: "Not available");
        let available = authenticationContext.canEvaluatePolicy(policy, error: &error);

        var results: [String : Any]

        if(error != nil){
            biometryType = "none";
            errorResponse["code"] = error?.code;
            errorResponse["message"] = error?.localizedDescription;
        }

        if (available == true) {
            if #available(iOS 11.0, *) {
                switch(authenticationContext.biometryType) {
                case .none:
                    biometryType = "none";
                case .touchID:
                    biometryType = "finger";
                case .faceID:
                    biometryType = "face"
                }
            }

            pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: biometryType);
        }else{
            var code: Int;
            switch(error!._code) {
                case Int(kLAErrorBiometryNotAvailable):
                    code = PluginError.BIOMETRIC_UNAVAILABLE.rawValue;
                    break;
                case Int(kLAErrorBiometryNotEnrolled):
                    code = PluginError.BIOMETRIC_NOT_ENROLLED.rawValue;
                    break;

                default:
                    code = PluginError.BIOMETRIC_UNKNOWN_ERROR.rawValue;
                    break;
            }
            results = ["code": code, "message": error!.localizedDescription];
            pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: results);
        }

        commandDelegate.send(pluginResult, callbackId:command.callbackId);
    }


    @objc(authenticate:)
    func authenticate(_ command: CDVInvokedUrlCommand){
        let authenticationContext = LAContext();
        var errorResponse: [AnyHashable: Any] = [
            "message": "Something went wrong"
        ];
        var pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: errorResponse);
        var reason = "Authentication";
        var policy:LAPolicy = .deviceOwnerAuthentication;
        let data  = command.arguments[0] as AnyObject?;

        if let disableBackup = data?["disableBackup"] as! Bool? {
            if disableBackup {
                authenticationContext.localizedFallbackTitle = "";
                policy = .deviceOwnerAuthenticationWithBiometrics;
            } else {
                if let fallbackButtonTitle = data?["fallbackButtonTitle"] as! String? {
                    authenticationContext.localizedFallbackTitle = fallbackButtonTitle;
                }else{
                    authenticationContext.localizedFallbackTitle = "Use Pin";
                }
            }
        }

        // Localized reason
        if let description = data?["description"] as! String? {
            reason = description;
        }

        authenticationContext.evaluatePolicy(
            policy,
            localizedReason: reason,
            reply: { [unowned self] (success, error) -> Void in
                if( success ) {
                    pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: "Success");
                }else {
                    if (error != nil) {

                        var errorCodes = [Int: ErrorCodes]()
                        var errorResult: [String : Any] = ["code":  PluginError.BIOMETRIC_UNKNOWN_ERROR.rawValue, "message": error?.localizedDescription ?? ""];

                        errorCodes[1] = ErrorCodes(code: PluginError.BIOMETRIC_AUTHENTICATION_FAILED.rawValue)
                        errorCodes[2] = ErrorCodes(code: PluginError.BIOMETRIC_DISMISSED.rawValue)
                        errorCodes[5] = ErrorCodes(code: PluginError.BIOMETRIC_SCREEN_GUARD_UNSECURED.rawValue)
                        errorCodes[6] = ErrorCodes(code: PluginError.BIOMETRIC_UNAVAILABLE.rawValue)
                        errorCodes[7] = ErrorCodes(code: PluginError.BIOMETRIC_NOT_ENROLLED.rawValue)
                        errorCodes[8] = ErrorCodes(code: PluginError.BIOMETRIC_LOCKED_OUT.rawValue)

                        let errorCode = abs(error!._code)
                        if let e = errorCodes[errorCode] {
                           errorResult = ["code": e.code, "message": error!.localizedDescription];
                        }

                        pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: errorResult);
                    }
                }
                self.commandDelegate.send(pluginResult, callbackId:command.callbackId);
            }
        );
    }

    override func pluginInitialize() {
        super.pluginInitialize()
    }
    
    
    //Call the below method to create a keypair and get public key
    @objc(retrieveKey:)
       func retrieveKey(_ command: CDVInvokedUrlCommand){
        
       do {
        var publicKey = try makeAndStoreKey(name: "com.durity.app", requiresBiometry: true)
        var pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAsString: publicKey);
       } catch let error {
        var pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR, messageAs: error.localizedDescription);
       }
       self.commandDelegate!.send(pluginResult, callbackId:command.callbackId);
    }
    
    func makeAndStoreKey(name: String,
                                requiresBiometry: Bool = false) throws -> String {
        //removeKey(name: name)
        let existingKey = KeychainHelper.loadKey(name: name)
        guard existingKey == nil else {//if key exists, return it
            return getPublicKey(privateKey: existingKey!)
        }

        let flags: SecAccessControlCreateFlags
        if #available(iOS 11.3, *) {
            flags = requiresBiometry ?
                [.privateKeyUsage, .biometryCurrentSet] : .privateKeyUsage
        } else {
            flags = requiresBiometry ?
                [.privateKeyUsage, .touchIDCurrentSet] : .privateKeyUsage
        }
        let access =
            SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                            flags,
                                            nil)!
        let tag = name.data(using: .utf8)!
        let attributes: [String: Any] = [
            kSecAttrKeyType as String           : kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String     : 256,
            kSecAttrTokenID as String           : kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String : [
                kSecAttrIsPermanent as String       : true,
                kSecAttrApplicationTag as String    : tag,
                kSecAttrAccessControl as String     : access
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        
        return getPublicKey(privateKey: privateKey)//return public key
    }
    
    private func getPublicKey(privateKey: SecKey) -> String {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            // Can't get public key
            return ""
        }
        var error: Unmanaged<CFError>?
        if let keyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? {
            return keyData.toHexString()
        } else {
            return ""
        }
    }
    
    func loadKey(name: String) -> SecKey? {
        let tag = name.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String                 : kSecClassKey,
            kSecAttrApplicationTag as String    : tag,
            kSecAttrKeyType as String           : kSecAttrKeyTypeEC,
            kSecReturnRef as String             : true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            return nil
        }
        return (item as! SecKey)
    }
    
//    func remove(key: String) {
//        let query = [
//            kSecClass as String       : kSecClassGenericPassword as String,
//            kSecAttrAccount as String : key]
//
//        SecItemDelete(query as CFDictionary)
//    }
    
};

module.exports = fingerprint;
