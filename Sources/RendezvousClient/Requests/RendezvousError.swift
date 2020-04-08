//
//  RendezvousError.swift
//  CEd25519
//
//  Created by Christoph on 10.01.20.
//

import Foundation

public enum RendezvousError: Int, Error {
    
    /// The server did not respond
    case noResponse = 0
    
    /// An unexpected error or HTTP status code
    case unknownError = 1
    
    /// The response from the server contained no data.
    case noDataInResponse = 2
    
    /// The data from the server is invalid or unreadable
    case invalidServerData = 3
    
    /// Some request data could not be serialized
    case serializationFailed = 4
    
    /// The downloaded file is invalid (hash mismatch, decryption/authentication failure)
    case invalidFile = 5
    
    /// The user has no permissions to write to the topic
    case noPermissionToWrite = 6
    
    // MARK: Server errors
    
    /// The request does not contain all necessary data, or some data is not properly formatted.
    case invalidRequest = 400
    
    /// The authentication for the request failed.
    case authenticationFailed = 401
    
    /// A signature for a request was invalid
    case invalidSignature = 406
    
    /// The user, device or topic already exists
    case resourceAlreadyExists = 409
    
    /// The request is too old to be processed.
    case requestOutdated = 410
    
    /// Invalid topic key signature, missing receiver, or missing device.
    case invalidTopicKeyUpload = 412
    
    /// The server produced an internal error
    case internalServerError = 500
    
    init(status: Int) {
        self = RendezvousError(rawValue: status) ?? .unknownError
    }
}
