//
//  Crypto.swift
//  RendezvousClient
//
//  Created by Christoph on 13.01.20.
//

import Foundation
import CryptoKit

private var set = false

public typealias EncryptionPublicKey = Curve25519.KeyAgreement.PublicKey
public typealias EncryptionPrivateKey = Curve25519.KeyAgreement.PrivateKey
public typealias SigningPublicKey = Curve25519.Signing.PublicKey
public typealias SigningPrivateKey = Curve25519.Signing.PrivateKey

public typealias EncryptionKeyPair = (private: EncryptionPrivateKey, public: EncryptionPublicKey)

enum Crypto {
    
    static func randomBytes(count: Int) -> Data? {
        var keyData = Data(count: count)
        let result = keyData.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        if result == errSecSuccess {
            return keyData
        } else {
            return nil
        }
    }

    static func encrypt(_ data: Data, to publicKey: Curve25519.KeyAgreement.PublicKey) throws -> Data {
        let ephemeralKey = EncryptionPrivateKey()
        let ephemeralPublicKey = ephemeralKey.publicKey.rawRepresentation
        let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: publicKey)
        
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Constants.protocolSalt, sharedInfo: ephemeralPublicKey + publicKey.rawRepresentation, outputByteCount: 32)
        
        let ciphertext = try AES.GCM.seal(data, using: symmetricKey).combined!
        return ephemeralPublicKey + ciphertext
    }
    
    static func decrypt(_ data: Data, using privateKey: Curve25519.KeyAgreement.PrivateKey) throws -> Data {
        guard data.count > Constants.eccKeyLength else {
            throw CryptoKitError.incorrectKeySize
        }
        let ephemeralPublicKeyData = data[0..<Constants.eccKeyLength]
        let ephemeralPublicKey = try EncryptionPublicKey(rawRepresentation: ephemeralPublicKeyData)
        
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
        
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Constants.protocolSalt,
            sharedInfo: ephemeralPublicKeyData + privateKey.publicKey.rawRepresentation,
            outputByteCount: 32)
        
        let sealedBox = try AES.GCM.SealedBox(combined: data.advanced(by: Constants.eccKeyLength))
        return try AES.GCM.open(sealedBox, using: symmetricKey)
    }
    
    static func newTopicId() -> TopicID {
        SymmetricKey(size: .init(bitCount: Constants.topicIdLength * 8))
            .withUnsafeBytes { Data(Array($0)) }
    }
    
    static func sha256(of data: Data) -> Data {
        SHA256.hash(data: data).withUnsafeBytes { Data(Array($0)) }
    }
    
    static func createPreKeys(count: Int, for device: SigningPrivateKey) throws -> (prekeys: [RV_DevicePrekey], keys: [EncryptionKeyPair])  {
        let keys: [EncryptionKeyPair] = (0..<count).map { _ in
            let privateKey = Curve25519.KeyAgreement.PrivateKey()
            return (privateKey, privateKey.publicKey)
        }
        
        // Sign the keys and package them
        let preKeys: [RV_DevicePrekey] = try keys.map { key in
            try RV_DevicePrekey.with {
                let preKey = key.public.rawRepresentation
                $0.preKey = preKey
                $0.signature = try device.signature(for: preKey)
            }
        }
        return (preKeys, keys)
    }
    
    static func createTopicKeys(count: Int, for userKey: SigningPrivateKey) throws -> [Topic.Keys] {
        try (0..<count).map { _ in
            try Topic.Keys(userKey: userKey)
        }
    }
    
    static func newEncryptionKey() -> EncryptionPrivateKey {
        .init()
    }
    
    static func newSigningKey() -> SigningPrivateKey {
        .init()
    }
    
    static func newMessageKey() -> SymmetricKey {
        .init(size: .bits256)
    }
}

extension EncryptionPublicKey: Equatable {
    
    public static func ==(lhs: EncryptionPublicKey, rhs: EncryptionPublicKey) -> Bool {
        return lhs.rawRepresentation == rhs.rawRepresentation
    }
}


extension SigningPublicKey: Equatable {
    
    public static func ==(lhs: SigningPublicKey, rhs: SigningPublicKey) -> Bool {
        return lhs.rawRepresentation == rhs.rawRepresentation
    }
}

extension AES.GCM.Nonce {
    
    var rawRepresentation: Data {
        self.withUnsafeBytes { Data(Array($0)) }
    }
}

extension SymmetricKey {
    
    var rawRepresentation: Data {
        self.withUnsafeBytes { Data(Array($0)) }
    }
}
