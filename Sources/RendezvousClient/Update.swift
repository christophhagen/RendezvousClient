//
//  Message.swift
//  Alamofire
//
//  Created by Christoph on 16.01.20.
//

import Foundation
import CryptoKit

public struct Update {
    
    public struct File {
        
        /// The id of the file
        public let id: MessageID
        
        /// The authentication tag of the file
        public let tag: Data
        
        /// The hash of the encrypted file
        public let hash: Data
        
        init(object: RV_TopicUpdate.File) {
            self.id = object.id
            self.hash = object.hash
            self.tag = object.tag
        }
        
        var object: RV_TopicUpdate.File {
            .with { file in
                file.id = id
                file.hash = hash
                file.tag = tag
            }
        }
    }
    
    /// The chain index for the current message
    public let chainIndex: UInt32
    
    /// The current output of the topic message chain
    public let output: Data
    
    /// The metadata of the file
    public let metadata: Data
    
    public let files: [File]
    
    /// The signature of the message
    let signature: Data
    
    /// The public key of the sender
    public let sender: SigningPublicKey
    
    init(object: RV_DeviceDownload.Message, metadata: Data, sender: SigningPublicKey) {
        self.chainIndex = object.chain.chainIndex
        self.output = object.chain.output
        self.metadata = metadata
        self.files = object.content.files.map(File.init)
        self.signature = object.content.signature
        self.sender = sender
    }
    
    init(object: RV_ClientData.TopicStore.UnverifiedMessage) throws {
        self.chainIndex = object.chain.chainIndex
        self.output = object.chain.output
        self.metadata = object.message.metadata
        self.signature = object.message.signature
        self.files = object.message.files.map(File.init)
        self.sender = try SigningPublicKey(rawRepresentation: object.senderPublicKey)
    }
    
    var object: RV_ClientData.TopicStore.UnverifiedMessage {
        .with {
            $0.senderPublicKey = sender.rawRepresentation
            $0.message = .with { message in
                message.metadata = metadata
                message.signature = signature
            }
            $0.chain = .with { chain in
                chain.chainIndex = chainIndex
                chain.output = output
            }
        }
    }
    
    public static func newMessageID() -> Data {
        AES.GCM.Nonce().rawRepresentation
    }
}
