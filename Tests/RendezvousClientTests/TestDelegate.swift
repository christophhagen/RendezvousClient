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
        self.count = count
    }
    
    var count: Int = 1
    
    var expectation: XCTestExpectation?
    
    var topic: Topic?
    
    var message: Message?
    
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
    
    func device(receivedMessage message: Message, in topic: Topic, verified: Bool) {
        self.message = message
        self.verified = verified
        decrement()
    }
    
    func device(foundInvalidChain index: Int, in topic: Topic) {
        XCTFail("Invalid chain \(index)")
        decrement()
    }
    
    
}
