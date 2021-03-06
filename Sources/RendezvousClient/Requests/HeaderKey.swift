//
//  File.swift
//  
//
//  Created by Christoph on 09.01.20.
//

import Foundation
import CryptoKit

/**
 An enum with all possible header keys used by Rendezvous.
 */
enum HeaderKey: String {
    
    /// The authentication token (admin, user, or device)
    case authToken = "auth"
    
    /// The user name, when a new user is created.
    case username = "username"
    
    /// The pin used for registration
    case pin = "pin"
    
    /// A public key of the user
    case user = "user"
    
    /// The public key of the device
    case device = "device"
    
    /// The number of keys or other items
    case count = "count"
    
    /// The public key of a requested user
    case receiver = "receiver"
    
    /// The identifier of the app.
    case appId = "app"
}
