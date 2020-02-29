//
//  DeviceDelegate.swift
//  Alamofire
//
//  Created by Christoph on 29.02.20.
//

import Foundation

public protocol DeviceDelegate: class {
    
    func user(changedDevice device: DeviceInfo)
    
    func user(addedDevice device: DeviceInfo)
    
    func user(removedDevice device: DeviceInfo)
    
    func device(addedTopic topic: Topic)
    
    func device(receivedMessage message: Update, in topic: Topic, verified: Bool)
    
    func device(didVerifyUpdate update: UInt32, in topic: Topic)
    
    func device(receivedChainState chainState: UInt32, for topic: TopicID, from sender: SigningPublicKey)
    
    func device(foundInvalidChain index: UInt32, in topic: Topic)
}
