//
//  BiometricAuthenticationServices.swift
//  BodyRx
//
//  Created by mac on 02/01/23.
//

import Foundation
import Combine

protocol BiometricAuthenticationServices {
    func canAuthenticate() -> AnyPublisher<Bool, Never>
    
    func authenticateWithBioMetrics(reason: String, fallbackTitle: String?, cancelTitle: String?) -> AnyPublisher<Bool, AuthenticationError>
    
    func authenticateWithPasscode(reason: String, cancelTitle: String?) -> AnyPublisher<Bool, AuthenticationError>
    
    func faceIDAvailable() -> AnyPublisher<Bool, Never>
    
    func touchIDAvailable() -> AnyPublisher<Bool, Never>
    
    func isFaceIdDevice() -> AnyPublisher<Bool, Never>
}
