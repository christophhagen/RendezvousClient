//
//  Message.swift
//  Alamofire
//
//  Created by Christoph on 16.01.20.
//

import Foundation
import CryptoKit

public struct Message {
    
    /// The chain index for the following message
    public let nextChainIndex: UInt32
    
    /// The current output of the topic message chain
    public let output: Data
    
    /// The id of the file
    public let id: MessageID
    
    /// The metadata of the file
    public let metadata: Data
    
    /// The authentication tag of the file
    public let tag: Data
    
    /// The hash of the encrypted file
    public let hash: Data
    
    /// The signature of the message
    let signature: Data
    
    /// The public key of the sender
    public let sender: SigningPublicKey
    
    init(object: RV_DeviceDownload.Message, metadata: Data, sender: SigningPublicKey) {
        self.nextChainIndex = object.chain.nextChainIndex
        self.output = object.chain.output
        self.id = object.content.id
        self.metadata = metadata
        self.tag = object.content.tag
        self.signature = object.content.signature
        self.hash = object.content.hash
        self.sender = sender
    }
    
    init(object: RV_ClientData.TopicStore.UnverifiedMessage) throws {
        self.nextChainIndex = object.chain.nextChainIndex
        self.output = object.chain.output
        self.id = object.id
        self.metadata = object.metadata
        self.tag = object.tag
        self.signature = object.signature
        self.hash = object.hash
        self.sender = try SigningPublicKey(rawRepresentation: object.senderPublicKey)
    }
    
    var object: RV_ClientData.TopicStore.UnverifiedMessage {
        .with {
            $0.senderPublicKey = sender.rawRepresentation
            $0.id = id
            $0.hash = hash
            $0.tag = tag
            $0.metadata = metadata
            $0.signature = signature
            $0.chain = .with { chain in
                chain.nextChainIndex = nextChainIndex
                chain.output = output
            }
        }
    }
    
    public static func newMessageID() -> Data {
        AES.GCM.Nonce().rawRepresentation
    }
}
