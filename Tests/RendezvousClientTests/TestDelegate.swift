//
//  TestDelegate.swift
//  RendezvousClientTests
//
//  Created by Christoph on 17.01.20.
//

import Foundation
import XCTest
import RendezvousClient

final class TestDelegate: DeviceDelegate {
    
    func set(expectation: XCTestExpectation, after count: Int = 1) {
        self.expectation = expectation
        topic = nil
        message = nil
        verified = false
        chainState = 0
        self.count = count
    }
    
    var count: Int = 1
    
    var expectation: XCTestExpectation?
    
    var topic: Topic?
    
    var message: Update?
    
    var chainState: UInt32 = 0
    
    var verified: Bool = false
    
    private func decrement() {
        count -= 1
        if count == 0 {
            expectation?.fulfill()
            expectation = nil
        }
    }
    
    func user(changedDevice device: DeviceInfo) {
        
    }
    
    func user(addedDevice device: DeviceInfo) {
        
    }
    
    func user(removedDevice device: DeviceInfo) {
        
    }
    
    func device(addedTopic topic: Topic) {
        self.topic = topic
        decrement()
    }
    
    func device(updatedTopic topic: Topic) {
        self.topic = topic
        decrement()
    }
    
    func device(receivedUpdate update: Update, in topic: Topic, verified: Bool) {
        self.message = update
        self.verified = verified
        decrement()
    }
    
    func device(receivedChainState chainState: UInt32, for topic: TopicID, from sender: SigningPublicKey) {
        self.chainState = chainState
        decrement()
    }
    
    func device(didVerifyUpdate update: UInt32, in topic: Topic) {
        decrement()
    }
    
    func device(foundInvalidChain index: UInt32, in topic: Topic) {
        XCTFail("Invalid chain \(index)")
        decrement()
    }
    
    
}
