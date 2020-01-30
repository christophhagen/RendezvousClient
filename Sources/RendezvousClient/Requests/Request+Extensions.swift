//
//  Request+Extensions.swift
//  
//
//  Created by Christoph on 09.01.20.
//

import Foundation
import Alamofire

extension HTTPHeaders {
    
    mutating func add(appId: String) {
        add(appId, for: .appId)
    }
    
    /**
     Add a count to the request.
    */
    mutating func add(count: Int) {
        add("\(count)", for: .count)
    }
    
    /**
     Add a user name to the request.
     */
    mutating func add(user: String) {
        add(user, for: .username)
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
