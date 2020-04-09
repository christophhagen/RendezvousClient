//
//  TopicKey.swift
//  Alamofire
//
//  Created by Christoph on 06.02.20.
//

import Foundation

extension Topic {
    
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
                message.role = role.object
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
