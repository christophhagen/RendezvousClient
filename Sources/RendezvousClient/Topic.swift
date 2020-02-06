//
//  Topic.swift
//  Alamofire
//
//  Created by Christoph on 15.01.20.
//

import Foundation
import CryptoKit

public class Topic {
    
    // MARK: Variables
    
    /// The unique id of the topic
    public let id: TopicID
    
    /// The date when the topic was created
    public let created: Date
    
    /// The date when the topic was last modified
    private(set) public var modified: Date
    
    /// The message key for encryption and decryption of messages
    private(set) public var messageKey: SymmetricKey
    
    /// The admins, participants and observers of the topic
    private(set) public var members: [Member]
    
    /// The key used for signing new messages to the topic
    public let signatureKey: SigningPrivateKey
    
    /// The key used to decrypt topic key messages
    public let encryptionKey: EncryptionPrivateKey
    
    /// The current message index  in the chain
    internal(set) public var chainIndex: UInt32
    
    /// The last output which could be verified.
    internal(set) public var verifiedOutput: Data
    
    /// All messages which couldn't be verified yet.
    internal(set) public var unverifiedMessages: [Update]
    
    // MARK: Initialization
    
    init(selfCreatedTopic topic: RV_Topic, withTopicKey topicKey: Keys, messageKey: SymmetricKey) throws {
        self.id = topic.topicID
        self.created = Date(seconds: topic.creationTime)
        self.modified = Date(seconds: topic.timestamp)
        self.messageKey = messageKey
        self.members = try topic.members.map(Member.init)
        self.signatureKey = topicKey.signing
        self.encryptionKey = topicKey.encryption
        self.chainIndex = 0
        self.verifiedOutput = topic.topicID
        self.unverifiedMessages = []
    }
    
    init(newTopic topic: RV_Topic, withTopicKey topicKey: Keys) throws {
        let ownKey = topicKey.publicKeys.userKey.rawRepresentation
        guard let message = topic.members.first(where: { $0.info.userKey == ownKey }) else {
            throw RendezvousError.unknownError
        }
        guard message.signatureKey == topicKey.publicKeys.signatureKey.rawRepresentation,
            message.info.encryptionKey == topicKey.publicKeys.encryptionKey.rawRepresentation else {
                throw RendezvousError.invalidRequest
        }
        let data = message.signatureKey + message.info.encryptionKey
        guard topicKey.publicKeys.userKey.isValidSignature(message.info.signature, for: data) else {
            throw RendezvousError.invalidSignature
        }
        // Decrypt the message key
        let decrypted = try Crypto.decrypt(message.encryptedMessageKey, using: topicKey.encryption)
        guard decrypted.count == Crypto.messageKeyLength, topic.topicID.count == Crypto.topicIdLength else {
            throw RendezvousError.unknownError
        }
        self.id = topic.topicID
        self.created = Date(seconds: topic.creationTime)
        self.modified = Date(seconds: topic.timestamp)
        self.messageKey = SymmetricKey(data: decrypted)
        self.members = try topic.members.map(Member.init)
        self.signatureKey = topicKey.signing
        self.encryptionKey = topicKey.encryption
        self.chainIndex = 0
        self.verifiedOutput = topic.topicID
        self.unverifiedMessages = []
    }
    
    // MARK: Storage
    
    init(object: RV_ClientData.TopicStore) throws {
        self.id = object.info.topicID
        self.created = Date(seconds: object.info.creationTime)
        self.modified = Date(seconds: object.info.timestamp)
        self.members = try object.info.members.map(Member.init)
        self.messageKey = SymmetricKey(data: object.messageKey)
        self.chainIndex = object.currentChainIndex
        self.verifiedOutput = object.verifiedOutput
        self.unverifiedMessages = try object.unverifiedMessages.map(Update.init)
        self.signatureKey = try SigningPrivateKey(rawRepresentation: object.signatureKey)
        self.encryptionKey = try EncryptionPrivateKey(rawRepresentation: object.encryptionKey)
    }
    
    var object: RV_ClientData.TopicStore {
        return .with {
            $0.info = topicObject
            $0.messageKey = messageKey.rawRepresentation
            $0.currentChainIndex = chainIndex
            $0.verifiedOutput = verifiedOutput
            $0.unverifiedMessages = unverifiedMessages.map { $0.object }
            $0.signatureKey = signatureKey.rawRepresentation
            $0.encryptionKey = encryptionKey.rawRepresentation
        }
    }
    
    private var topicObject: RV_Topic {
        .with {
            $0.topicID = id
            $0.creationTime = created.seconds
            $0.timestamp = modified.seconds
            $0.members = members.map { $0.object }
        }
    }
    
    func processMessages(update: Update, delegate: DeviceDelegate?) {
        unverifiedMessages.append(update)
        
        // This is to ensure that the delegate is notified exactly once for the incoming message
        var verifiedIncomingMessage = false
        defer {
            delegate?.device(receivedMessage: update, in: self, verified: verifiedIncomingMessage)
        }
        
        // Sort so that oldest messages are at the end
        unverifiedMessages.sort { $0.chainIndex > $1.chainIndex }
        while let next = unverifiedMessages.last {
            // See if the topic state can be verified.
            guard next.chainIndex == chainIndex + 1 else {
                return
            }
            
            // Calculate the new output
            let output = Crypto.sha256(of: verifiedOutput + next.signature)
            guard output == next.output else {
                // Invalid chain. This implies an inconsistency in the message chain,
                // which could indicate that the server is attempting to tamper with
                // the messages
                delegate?.device(foundInvalidChain: next.chainIndex, in: self)
                return
            }
            // Remove handled update
            _ = unverifiedMessages.popLast()
            
            // Update the topic state
            chainIndex = next.chainIndex
            verifiedOutput = output
            
            // This is to ensure that the delegate is notified exactly once for the incoming message
            if next.chainIndex == update.chainIndex {
                verifiedIncomingMessage = true
            } else {
                delegate?.device(receivedMessage: next, in: self, verified: true)
            }
        }
    }
    
}
