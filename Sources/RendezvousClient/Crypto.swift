//
//  Crypto.swift
//  RendezvousClient
//
//  Created by Christoph on 13.01.20.
//

import Foundation
import CryptoKit25519
import CryptoSwift

private var set = false

public typealias EncryptionPublicKey = Curve25519.KeyAgreement.PublicKey
public typealias EncryptionPrivateKey = Curve25519.KeyAgreement.PrivateKey

public typealias SigningPublicKey = Curve25519.Signing.PublicKey
public typealias SigningPrivateKey = Curve25519.Signing.PrivateKey

enum Crypto {
    
    static let topicIdLength = 12
    
    static let messageKeyLength = 32
    
    static let protocolSalt = "RendezvousClient".data(using: .utf8)!
    
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
    
    static func ensureRandomness() {
        guard !set else {
            return
        }
        Randomness.source = randomBytes(count:)
        set = true
    }
    
    static func encrypt(_ data: Data, to publicKey: EncryptionPublicKey) throws -> Data {
        let ephemeralKey = try EncryptionPrivateKey()
        let ephemeralPublicKey = ephemeralKey.publicKey.rawRepresentation
        let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: publicKey)
        
        let symmetricKey = try sharedSecret.hkdfDerivedSymmetricKey(
            using: .sha256,
            salt: protocolSalt,
            sharedInfo: ephemeralPublicKey + publicKey.rawRepresentation,
            outputByteCount: 32)
        
        let ciphertext = try AES.GCM.seal(data, using: symmetricKey).combined
        return ephemeralPublicKey + ciphertext
    }
    
    static func decrypt(_ data: Data, using privateKey: EncryptionPrivateKey) throws -> Data {
        guard data.count > Curve25519.keyLength else {
            throw CryptoKitError.invalidKeyLength
        }
        let ephemeralPublicKeyData = data[0..<Curve25519.keyLength]
        let ephemeralPublicKey = try EncryptionPublicKey(rawRepresentation: ephemeralPublicKeyData)
        
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
        
        let symmetricKey = try sharedSecret.hkdfDerivedSymmetricKey(
            using: .sha256,
            salt: protocolSalt,
            sharedInfo: ephemeralPublicKeyData + privateKey.publicKey.rawRepresentation,
            outputByteCount: 32)
        
        let sealedBox = try AES.GCM.SealedBox(combined: data.advanced(by: Curve25519.keyLength))
        return try AES.GCM.open(sealedBox, using: symmetricKey)
    }
    
    static func newTopicId() throws -> Data {
        guard let bytes = randomBytes(count: topicIdLength) else {
            throw CryptoKitError.noRandomnessAvailable
        }
        return bytes
    }
    
    static func SHA256(_ data: Data) -> Data {
        Data(SHA2(variant: .sha256).calculate(for: (data.bytes)))
    }
    
}

extension Data {
    
    var signingPublicKey: SigningPublicKey? {
        return try? SigningPublicKey(rawRepresentation: self)
    }
    
    var encryptionPublicKey: EncryptionPublicKey? {
        return try? EncryptionPublicKey(rawRepresentation: self)
    }
}
