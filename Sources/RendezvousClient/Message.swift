//
//  Message.swift
//  Alamofire
//
//  Created by Christoph on 16.01.20.
//

import Foundation

public struct Message {
    
    public let index: Int
    
    public let output: Data
    
    public let id: Data
    
    public let metadata: Data
    
    public let hash: Data
    
    let signature: Data
    
    public let sender: SigningPublicKey
    
    init(object: RV_DeviceDownload.Message, metadata: Data, sender: SigningPublicKey) {
        self.index = Int(object.chain.nextChainIndex) - 1
        self.output = object.chain.output
        self.id = object.content.id
        self.metadata = metadata
        self.signature = object.content.signature
        self.hash = object.content.hash
        self.sender = sender
    }
}
