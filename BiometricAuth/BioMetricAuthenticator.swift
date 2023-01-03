//
//  BioMetricAuthenticator.swift
//  BiometricAuthentication
//
//  Copyright (c) 2018 Rushi Sangani
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

import UIKit
import LocalAuthentication
import Combine

final class BioMetricAuthenticator: NSObject{
    // MARK: - Public
    public var allowableReuseDuration: TimeInterval = 0
    
    // MARK: - Private
    private var cancellables = Set<AnyCancellable>()
}

// MARK:- Public

extension BioMetricAuthenticator: BiometricAuthenticationServices {
    /// checks if biometric authentication can be performed currently on the device.
    func canAuthenticate() -> AnyPublisher<Bool, Never> {
        return Future<Bool, Never> { promise in
            var isBiometricAuthenticationAvailable = false
            var error: NSError? = nil
            
            if LAContext().canEvaluatePolicy(
                LAPolicy.deviceOwnerAuthenticationWithBiometrics,
                error: &error
            ) {
                isBiometricAuthenticationAvailable = (error == nil)
            }
            promise(.success(isBiometricAuthenticationAvailable))
        }.eraseToAnyPublisher()
    }
    
    /// Check for biometric authentication
    func authenticateWithBioMetrics(reason: String, fallbackTitle: String? = "", cancelTitle: String? = "") -> AnyPublisher<Bool, AuthenticationError> {
        return Future<Bool, AuthenticationError> { [weak self] promise in
            // reason
            let reasonString = reason.isEmpty ? self?.defaultBiometricAuthenticationReason() : reason
            
            // context
            let context = LAContext()
            context.touchIDAuthenticationAllowableReuseDuration = self?.allowableReuseDuration ?? 0
            context.localizedFallbackTitle = fallbackTitle
            context.localizedCancelTitle = cancelTitle
            
            // authenticate
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reasonString ?? "") { (success, err) in
                DispatchQueue.main.async {
                    if success {
                        promise(.success(true))
                    }else {
                        let errorType = AuthenticationError.initWithError(err as! LAError)
                        promise(.failure(errorType))
                    }
                }
            }
        }.eraseToAnyPublisher()
    }
    
    /// Check for device passcode authentication
    func authenticateWithPasscode(reason: String, cancelTitle: String?) -> AnyPublisher<Bool, AuthenticationError> {
        return Future<Bool, AuthenticationError> { [weak self] promise in
            // reason
            let reasonString = reason.isEmpty ? self?.defaultPasscodeAuthenticationReason() : reason
            
            let context = LAContext()
            context.localizedCancelTitle = cancelTitle
            
            // authenticate
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reasonString ?? "") { (success, err) in
                DispatchQueue.main.async {
                    if success {
                        promise(.success(true))
                    }else {
                        let errorType = AuthenticationError.initWithError(err as! LAError)
                        promise(.failure(errorType))
                    }
                }
            }
        }.eraseToAnyPublisher()
    }
    
    /// checks if device supports face id and authentication can be done
    func faceIDAvailable() -> AnyPublisher<Bool, Never> {
        return Future<Bool, Never> { promise in
            let context = LAContext()
            var error: NSError?
            
            let canEvaluate = context.canEvaluatePolicy(
                LAPolicy.deviceOwnerAuthenticationWithBiometrics,
                error: &error
            )
            promise(.success(canEvaluate && context.biometryType == .faceID))
        }.eraseToAnyPublisher()
    }
    
    /// checks if device supports touch id and authentication can be done
    func touchIDAvailable() -> AnyPublisher<Bool, Never> {
        return Future<Bool, Never> { promise in
            let context = LAContext()
            var error: NSError?
            
            let canEvaluate = context.canEvaluatePolicy(
                LAPolicy.deviceOwnerAuthenticationWithBiometrics,
                error: &error
            )
            promise(.success(canEvaluate && context.biometryType == .touchID))
        }.eraseToAnyPublisher()
    }
    
    /// checks if device has faceId
    /// this is added to identify if device has faceId or touchId
    /// note: this will not check if devices can perform biometric authentication
    func isFaceIdDevice() -> AnyPublisher<Bool, Never> {
        return Future<Bool, Never> { promise in
            let context = LAContext()
            _ = context.canEvaluatePolicy(LAPolicy.deviceOwnerAuthenticationWithBiometrics, error: nil)
            promise(.success(context.biometryType == .faceID))
        }.eraseToAnyPublisher()
    }
}

// MARK:- Private
extension BioMetricAuthenticator {
    /// get authentication reason to show while authentication
    private func defaultBiometricAuthenticationReason() -> String {
        var reason = ""
        faceIDAvailable().sink { isAvailable in
            if isAvailable {
                reason = Constant.shared.kFaceIdAuthenticationReason
            } else {
                reason = Constant.shared.kTouchIdAuthenticationReason
            }
        }.store(in: &cancellables)
        return reason
    }
    
    /// get passcode authentication reason to show while entering device passcode after multiple failed attempts.
    private func defaultPasscodeAuthenticationReason() -> String {
        var reason = ""
        faceIDAvailable().sink { isAvailable in
            if isAvailable {
                reason = Constant.shared.kFaceIdPasscodeAuthenticationReason
            } else {
                reason = Constant.shared.kTouchIdPasscodeAuthenticationReason
            }
        }.store(in: &cancellables)
        return reason
    }
}
