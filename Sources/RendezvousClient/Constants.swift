//
//  Constants.swift
//  Alamofire
//
//  Created by Christoph on 03.02.20.
//

import Foundation

/// The public identity key of a device
public typealias DeviceKey = Data

/// The public identity key of a user
public typealias UserKey = Data

/// The id of a topic
public typealias TopicID = Data

/// The id of a message
public typealias FileID = Data

/// An authentication token
public typealias AuthToken = Data


public enum Constants {
    
    /// The time interval after which pins expire (in seconds)
    public static let pinExpiryInterval: UInt32 = 60 * 60 * 32 * 7
    
    /// The number of times a pin can be wrong before blocking the registration
    public static let pinAllowedTries: UInt32 = 3
    
    /// The maximum value for the pin
    public static let pinMaximum: UInt32 = 100000
    
    /// The maximum allowed characters for user names
    public static let maximumNameLength = 32
    
    /// The number of bytes for an authentication token
    public static let authTokenLength = 16
    
    /// The length of a topic id
    public static let topicIdLength = 12
    
    /// The length of a message id
    public static let messageIdLength = 12
    
    /// The maximum length of an app id
    public static let maximumAppIdLength = 10
    
    /// The maximum length of message metadata
    public static let maximumMetadataLength = 100
    
    /// The length of an elliptic curve key
    static let eccKeyLength = 32
    
    /// The length of a message key
    static let messageKeyLength = 32
    
    /// The salt used for the protocol when encrypting data
    static let protocolSalt = "Rendezvous".data(using: .utf8)!
    
    
    
}
