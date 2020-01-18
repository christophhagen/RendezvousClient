//
//  Request+Extensions.swift
//  
//
//  Created by Christoph on 09.01.20.
//

import Foundation
import CryptoKit25519
import Alamofire

extension URLRequest {
    
    /**
     Add binary data to the request.
     */
    mutating func add(body: Data) {
        self.httpBody = body
    }
    
    /**
     Add a value for a key in the request header.
     - Parameter value: The value to set.
     - Parameter header: The key of the header.
     */
    private mutating func add(_ value: String, for header: HeaderKey) {
        addValue(value, forHTTPHeaderField: header.rawValue)
    }
    
    /**
     Add a binary value for a header field.
     - Parameter value: The value to set.
     - Parameter header: The key of the header.
     */
    private mutating func add(binary value: Data, for key: HeaderKey) {
        add(value.base64EncodedString(), for: key)
    }
    
    /**
     Add an authentication token.
     - Parameter authToken: The binary authentication token.
     */
    mutating func add(authToken: Data) {
        add(binary: authToken, for: .authToken)
    }
    
    /**
     Add a user name to the request.
     */
    mutating func add(user: String) {
        add(user, for: .username)
    }
    
    /**
     Add a pin to the request.
    */
    mutating func add(pin: Int) {
        add("\(pin)", for: .pin)
    }
    
    /**
     Add a count to the request.
    */
    mutating func add(count: Int) {
        add("\(count)", for: .count)
    }
    
    /**
     Add the public key of the device.
     */
    mutating func add(devicePublicKey: SigningPublicKey) {
        add(publicKey: devicePublicKey, for: .device)
    }
    
    /**
    Add the public key of the user.
    */
    mutating func add(userPublicKey: SigningPublicKey) {
        add(publicKey: userPublicKey, for: .user)
    }
    
    private mutating func add(publicKey: SigningPublicKey, for key: HeaderKey) {
        add(binary: publicKey.rawRepresentation, for: key)
    }
}

extension HTTPHeaders {
    
    /**
     Add a count to the request.
    */
    mutating func add(count: Int) {
        add("\(count)", for: .count)
    }
    
    /**
     Add an authentication token.
     - Parameter authToken: The binary authentication token.
     */
    mutating func add(authToken: Data) {
        add(binary: authToken, for: .authToken)
    }
    
    /**
     Add the public key of the receiver.
     - Parameter receiverKey: The public key to add as a receiver identity key.
     */
    mutating func add(receiverKey: SigningPublicKey) {
        add(publicKey: receiverKey, for: .receiver)
    }
    
    /**
     Add the public key of the device.
     - Parameter deviceKey: The public key to add as a device identity key.
     */
    mutating func add(deviceKey: SigningPublicKey) {
        add(publicKey: deviceKey, for: .device)
    }
    
    /**
    Add the public key of the user.
    - Parameter userKey: The public key to add as a user identity key.
    */
    mutating func add(userKey: SigningPublicKey) {
        add(publicKey: userKey, for: .user)
    }
    
    /**
     Add a public key for a header key.
     - Parameter publicKey: The public key to add.
     - Parameter key: The HTTP header key.
     */
    private mutating func add(publicKey: SigningPublicKey, for key: HeaderKey) {
        add(binary: publicKey.rawRepresentation, for: key)
    }
    
    /**
     Add a binary value for a header field.
     - Parameter value: The value to set.
     - Parameter header: The key of the header.
     */
    private mutating func add(binary value: Data, for key: HeaderKey) {
        add(value.base64EncodedString(), for: key)
    }
    
    /**
     Add a value for a key in the request header.
     - Parameter value: The value to set.
     - Parameter header: The key of the header.
     */
    private mutating func add(_ value: String, for header: HeaderKey) {
        add(name: header.rawValue, value: value)
    }
}
