//
//  Message.swift
//  Alamofire
//
//  Created by Christoph on 16.01.20.
//

import Foundation
import CryptoKit

public struct Update {
    
    public struct File: Equatable {
        
        /// The id of the file
        public let id: FileID
        
        /// The authentication tag of the file
        public let tag: Data
        
        /// The hash of the encrypted file
        public let hash: Data
        
        /**
         Create a new file with a random ID before uploading it to the server.
         - Note: `tag` and `hash` will be left empty
         */
        public init() {
            self.id = Update.newFileID()
            self.tag = Data()
            self.hash = Data()
        }
        
        public init(id: FileID, tag: Data, hash: Data) {
            self.id = id
            self.tag = tag
            self.hash = hash
        }
        
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
    
    init(update: RV_TopicUpdate, chain: RV_TopicState.ChainState, sender: SigningPublicKey) {
        self.chainIndex = chain.chainIndex
        self.output = chain.output
        self.metadata = update.metadata
        self.signature = update.signature
        self.sender = sender
        self.files = update.files.map(File.init)
    }
    
    init(object: RV_DeviceDownload.Message, metadata: Data, sender: SigningPublicKey) {
        self.chainIndex = object.chain.chainIndex
        self.output = object.chain.output
        self.metadata = metadata
        self.files = object.content.files.map(File.init)
        self.signature = object.content.signature
        self.sender = sender
    }
    
    /**
     Create a new file id.
     
     - Returns: The random file id.
     */
    public static func newFileID() -> Data {
        AES.GCM.Nonce().rawRepresentation
    }
    
    /// The info to verify the message chain
    var essence: Essence {
        Essence(chainIndex: chainIndex, output: output, signature: signature)
    }
    
    /// The necessary info needed to verify the message chain
    public struct Essence {
        
        /// The chain index for the current message
        public let chainIndex: UInt32
        
        /// The current output of the topic message chain
        public let output: Data
        
        /// The signature of the message
        let signature: Data
        
        init(chainIndex: UInt32, output: Data, signature: Data) {
            self.chainIndex = chainIndex
            self.output = output
            self.signature = signature
        }
        
        init(object: RV_ClientData.TopicStore.UnverifiedMessage) throws {
            self.chainIndex = object.chainIndex
            self.output = object.output
            self.signature = object.signature
        }
        
        var object: RV_ClientData.TopicStore.UnverifiedMessage {
            .with {
                $0.signature = signature
                $0.chainIndex = chainIndex
                $0.output = output
            }
        }
        
    }
}
