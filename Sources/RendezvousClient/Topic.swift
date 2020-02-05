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
    
    /// The next message index expected in the chain
    internal(set) public var nextChainIndex: UInt32
    
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
        self.nextChainIndex = 0
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
        self.nextChainIndex = 0
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
        self.nextChainIndex = object.nextChainIndex
        self.verifiedOutput = object.verifiedOutput
        self.unverifiedMessages = try object.unverifiedMessages.map(Update.init)
        self.signatureKey = try SigningPrivateKey(rawRepresentation: object.signatureKey)
        self.encryptionKey = try EncryptionPrivateKey(rawRepresentation: object.encryptionKey)
    }
    
    var object: RV_ClientData.TopicStore {
        return .with {
            $0.info = topicObject
            $0.messageKey = messageKey.rawRepresentation
            $0.nextChainIndex = nextChainIndex
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
    
    // MARK: Members
    
    /// A member of a topic
    public struct Member {
        
        /// The user identity key
        public let userKey: SigningPublicKey
        
        /// The signature key used when signing new messages
        public let signatureKey: SigningPublicKey
        
        /// The encryption key used to encrypt the message key
        public let encryptionKey: EncryptionPublicKey
        
        /// The permissions of the member
        private(set) public var role: Role
        
        /**
         Create a member from a protobuf object.
         
         - Parameter member: The protobuf object with the info
         */
        init(member: RV_Topic.MemberInfo) throws {
            self.userKey = try SigningPublicKey(rawRepresentation: member.info.userKey)
            self.signatureKey = try SigningPublicKey(rawRepresentation: member.signatureKey)
            self.encryptionKey = try EncryptionPublicKey(rawRepresentation: member.info.encryptionKey)
            self.role = try Role(raw: member.role)
        }
        
        var object: RV_Topic.MemberInfo {
            .with {
                $0.signatureKey = signatureKey.rawRepresentation
                $0.role = role.raw
            }
        }
        
        // MARK: Roles

        public enum Role {
            
            /// Admins are allowed to add and remove users, and read and write messages
            case admin
            
            /// Participants are allowed to read and write messages
            case participant
            
            /// Observers are allowed to read messages
            case observer
            
            var raw: RV_Topic.MemberInfo.Role {
                switch self {
                case .admin: return .admin
                case .participant: return .participant
                case .observer: return .observer
                }
            }
            
            init(raw: RV_Topic.MemberInfo.Role) throws {
                switch raw {
                case .admin: self = .admin
                case .participant: self = .participant
                case .observer: self = .observer
                default:
                    throw RendezvousError.unknownError
                }
            }
        }
    }
    
    // MARK: Private topic keys
    
    struct Keys {
        
        let signing: SigningPrivateKey
        
        let encryption: EncryptionPrivateKey
        
        let publicKeys: Key
        
        init(userKey: SigningPrivateKey) throws {
            let signing = SigningPrivateKey()
            let encryption = EncryptionPrivateKey()
            
            self.signing = signing
            self.encryption = encryption
            self.publicKeys = try Key(userKey: userKey, signatureKey: signing.publicKey, encryptionKey: encryption.publicKey)
        }
        
        init(message: RV_TopicKeyMessage, preKey: EncryptionPrivateKey, userKey: SigningPublicKey) throws {
            // Verify the topic key
            let topicKey = try Key(object: message.topicKey, userKey: userKey)

            // Decrypt the topic key
            let decrypted = try Crypto.decrypt(message.encryptedTopicKeys, using: preKey)
            guard decrypted.count == Crypto.eccKeyLength * 2 else {
                throw RendezvousError.unknownError
            }
            
            // Extract signature and encryption key
            let signaturePrivateKey = try! SigningPrivateKey(rawRepresentation: decrypted[0..<Crypto.eccKeyLength])
            let encryptionPrivateKey = try! EncryptionPrivateKey(rawRepresentation: decrypted.advanced(by: Crypto.eccKeyLength))
            
            // Check that public keys match
            guard signaturePrivateKey.publicKey == topicKey.signatureKey,
                encryptionPrivateKey.publicKey == topicKey.encryptionKey else {
                    throw RendezvousError.unknownError
            }
            
            // Store the topic key
            self.signing = signaturePrivateKey
            self.encryption = encryptionPrivateKey
            self.publicKeys = topicKey
        }
        
        init(object: RV_ClientData.TopicKeyPair, userKey: SigningPublicKey) throws {
            self.signing = try SigningPrivateKey(rawRepresentation: object.signing.privateKey)
            self.encryption = try EncryptionPrivateKey(rawRepresentation: object.encryption.privateKey)
            self.publicKeys = try .init(object: object, userKey: userKey)
        }
        
        var object: RV_ClientData.TopicKeyPair {
            return .with { key in
                key.signing = .with {
                    $0.privateKey = signing.rawRepresentation
                    $0.publicKey = publicKeys.signatureKey.rawRepresentation
                }
                key.encryption = .with {
                    $0.privateKey = encryption.rawRepresentation
                    $0.publicKey = publicKeys.encryptionKey.rawRepresentation
                }
                key.signature = publicKeys.signature
            }
        }
        
        func message(withPrekey key: RV_DevicePrekey) throws -> RV_TopicKeyMessage {
            return try .with { message in
                message.devicePreKey = key.preKey
                message.topicKey = publicKeys.object
                let data = publicKeys.signatureKey.rawRepresentation + publicKeys.encryptionKey.rawRepresentation
                let preKey = try EncryptionPublicKey(rawRepresentation: key.preKey)
                message.encryptedTopicKeys = try Crypto.encrypt(data, to: preKey)
            }
        }
    }
    
    // MARK: Public topic keys
    
    struct Key {
        
        let userKey: SigningPublicKey
        
        let signatureKey: SigningPublicKey
        
        let encryptionKey: EncryptionPublicKey
        
        /// The signature of (signatureKey | encryptionKey) with the user key
        let signature: Data
        
        init(userKey: SigningPrivateKey, signatureKey: SigningPublicKey, encryptionKey: EncryptionPublicKey) throws {
            let data = signatureKey.rawRepresentation + encryptionKey.rawRepresentation
            self.userKey = userKey.publicKey
            self.signatureKey = signatureKey
            self.encryptionKey = encryptionKey
            self.signature = try userKey.signature(for: data)
        }
        
        init(object: RV_TopicKeyResponse.User) throws {
            guard let userKey = try? SigningPublicKey(rawRepresentation: object.publicKey) else {
                throw RendezvousError.unknownError
            }
            try self.init(object: object.topicKey, userKey: userKey)
        }
        
        init(object: RV_TopicKey, userKey: SigningPublicKey) throws {
            guard userKey.isValidSignature(object.signature, for: object.signatureKey + object.encryptionKey) else {
                throw RendezvousError.invalidSignature
            }
            guard let signatureKey = try? SigningPublicKey(rawRepresentation: object.signatureKey),
                let encryptionKey = try? EncryptionPublicKey(rawRepresentation: object.encryptionKey) else {
                    throw RendezvousError.unknownError
            }
            
            self.userKey = userKey
            self.signatureKey = signatureKey
            self.encryptionKey = encryptionKey
            self.signature = object.signature
        }
        
        init(object: RV_ClientData.TopicKeyPair, userKey: SigningPublicKey) throws {
            self.signatureKey = try SigningPublicKey(rawRepresentation: object.signing.publicKey)
            self.encryptionKey = try EncryptionPublicKey(rawRepresentation: object.encryption.privateKey)
            self.signature = object.signature
            self.userKey = userKey
        }
        
        init(data: Data, userKey: SigningPublicKey) throws {
            let object: RV_TopicKey
            do {
                object = try RV_TopicKey(serializedData: data)
            } catch {
                throw RendezvousError.noResponse
            }
            try self.init(object: object, userKey: userKey)
        }
        
        func encrypt(_ data: Data, role: Topic.Member.Role) throws -> RV_Topic.MemberInfo {
            try .with { message in
                message.signatureKey = signatureKey.rawRepresentation
                message.role = role.raw
                message.encryptedMessageKey = try Crypto.encrypt(data, to: encryptionKey)
                message.info = .with {
                    $0.userKey = userKey.rawRepresentation
                    $0.encryptionKey = encryptionKey.rawRepresentation
                    $0.signature = signature
                }
                
            }
        }
        
        var object: RV_TopicKey {
            .with {
                $0.signatureKey = signatureKey.rawRepresentation
                $0.encryptionKey = encryptionKey.rawRepresentation
                $0.signature = signature
            }
        }
        
        static func from(data: Data) throws -> [Key] {
            let object = try RV_TopicKeyResponse(serializedData: data)
            return try object.users.map(Key.init)
        }
    }
}
