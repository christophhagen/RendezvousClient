//
//  CryptoTests.swift
//  Alamofire
//
//  Created by Christoph on 13.01.20.
//

import XCTest
import Foundation
import CryptoKit25519
import CryptoSwift
import CCurve25519

@testable import RendezvousClient

final class CryptoTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        Crypto.ensureRandomness()
    }
    
    static var allTests = [
        ("testEncryption", testEncryption),
    ]

    func testEncryption() throws {
        let privateKey = try EncryptionPrivateKey()
        let plaintext = "SomeRandomData".data(using: .utf8)!
        
        print("Encrypting")
        let ciphertext = try Crypto.encrypt(plaintext, to: privateKey.publicKey)
        
        print("Decrypting \(ciphertext)")
        let decrypted = try Crypto.decrypt(ciphertext, using: privateKey)
        XCTAssertEqual(plaintext, decrypted)
    }
    
    func testOne() throws {
        let key = try SymmetricKey(size: .init(bitCount: 256))
        let message = "SomeRandomData".data(using: .utf8)!
        
        let box = try AES.GCM.seal(message, using: key)
        
        let plaintext = try AES.GCM.open(box, using: key)
        
        XCTAssertEqual(plaintext, message)
    }
    
    func testKeyAgreement() throws {
        let privateKey1 = try EncryptionPrivateKey()
        let privateKey2 = try EncryptionPrivateKey()
        
        let symmetricKey1 = try privateKey1.sharedSecretFromKeyAgreement(with: privateKey2.publicKey)
        let symmetricKey2 = try privateKey2.sharedSecretFromKeyAgreement(with: privateKey1.publicKey)
        
        XCTAssertEqual(symmetricKey1, symmetricKey2)
        
    }
    
    func testKeys() throws {
        let privateKey1 = try EncryptionPrivateKey()
        let priv1 = privateKey1.rawRepresentation.bytes
        let publicKey1 = try EncryptionPrivateKey().publicKey
        let pub1 = publicKey1.rawRepresentation
        
        var sharedKey = [UInt8](repeating: 0, count: Curve25519.keyLength)
        let result: Int32 = sharedKey.withUnsafeMutableBytes { s in
            priv1.withUnsafeBytes { priv in
                pub1.bytes.withUnsafeBytes { pub in
                    curve25519_donna(
                        s.bindMemory(to: UInt8.self).baseAddress,
                        priv.bindMemory(to: UInt8.self).baseAddress,
                        pub.bindMemory(to: UInt8.self).baseAddress)
                }
            }
        }
        XCTAssertEqual(result, 0)
        
        let shared = try privateKey1.sharedSecretFromKeyAgreement(with: publicKey1)
        XCTAssertEqual(sharedKey, shared.rawData.bytes)
    }
    
    func testTwo() throws {
        let iv = Randomness.source!(12)!
        let key = Randomness.source!(32)!
        let message = "SomeRandomData".data(using: .utf8)!
        
        let gcm = CryptoSwift.GCM.init(
            iv: iv.bytes,
            additionalAuthenticatedData: nil,
            tagLength: 16,
            mode: .detached)
        
        let ciphertext: [UInt8]
        do {
            let cryptor = try CryptoSwift.AES(key: key.bytes, blockMode: gcm, padding: .pkcs7)
            ciphertext = try cryptor.encrypt(message.bytes)
        } catch {
            throw CryptoKitError.encryptionFailed
        }
        
        let tag = Data(gcm.authenticationTag!)
        
        let gcm2 = CryptoSwift.GCM(
            iv: iv.bytes,
            authenticationTag: tag.bytes,
            additionalAuthenticatedData: nil)
        let plaintext: [UInt8]
        do {
            let cryptor = try CryptoSwift.AES(key: key.bytes, blockMode: gcm2, padding: .pkcs7)
            plaintext = try cryptor.decrypt(ciphertext)
        } catch {
            throw CryptoKitError.decryptionFailed
        }
        
        XCTAssertEqual(plaintext, message.bytes)
        
    }
    
}


private extension UnsafeRawBufferPointer {
    
    /// The forcefully unwrapped pointer to the data
    var dataPtr: UnsafePointer<UInt8> {
        return baseAddress!.assumingMemoryBound(to: UInt8.self)
    }
}

private extension UnsafeMutableRawBufferPointer {
    
    /// The forcefully unwrapped pointer to the data
    var dataPtr: UnsafeMutablePointer<UInt8> {
        return baseAddress!.assumingMemoryBound(to: UInt8.self)
    }
}
