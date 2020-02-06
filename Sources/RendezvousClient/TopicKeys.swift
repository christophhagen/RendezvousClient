//
//  TopicKeys.swift
//  Alamofire
//
//  Created by Christoph on 06.02.20.
//

import Foundation

extension Topic {
    
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
}
