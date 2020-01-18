//
//  DeviceConnection.swift
//  Alamofire
//
//  Created by Christoph on 10.01.20.
//

import Foundation
import CryptoKit25519
import Alamofire
import CryptoSwift

public protocol DeviceDelegate: class {
    
    func device(addedTopic topic: Topic)
    
    func device(receivedMessage message: Message, in topic: Topic, verified: Bool)
    
    func device(foundInvalidChain index: Int, in topic: Topic)
}

public final class Device: User {
    
    /// The private key of the device
    let devicePrivateKey: SigningPrivateKey
    
    /// The public key of the device
    let deviceKey: SigningPublicKey
    
    let authToken: Data
    
    var preKeys = [EncryptionPublicKey : EncryptionPrivateKey]()
    
    var topicKeys = [SigningPublicKey: Topic.Keys]()
    
    var topics = [Data : Topic]()
    
    public weak var delegate: DeviceDelegate?
    
    /**
     Create a device.
     */
    init(url: URL, userKey: SigningPrivateKey, info: RV_InternalUser,  deviceKey: SigningPrivateKey, authToken: Data) {
        self.devicePrivateKey = deviceKey
        self.deviceKey = deviceKey.publicKey
        self.authToken = authToken
        super.init(url: url, userKey: userKey, info: info)
        
    }
    
    public enum NotificationType: Int {
        
        /// No push capabilities for the device
        case pushDisabled = 0
        
        /// The device is a regular iOS device
        case iOSDevice = 1
        
        /// The device is used for iOS development
        case iOSDevelopmentDevice = 2
        
        /// The device is a regular iOS device using a notification extension
        case iOSNotificationExtension = 3
        
        /// The device is a development iOS device using a notification extension
        case iOSDevelopmentNotificationExtension = 4
    }
    
    private var authenticatedHeaders: HTTPHeaders {
        var headers: HTTPHeaders = []
        headers.add(userKey: userKey)
        headers.add(deviceKey: deviceKey)
        headers.add(authToken: authToken)
        return headers
    }
    
    static func createPreKeys(count: Int, for device: SigningPrivateKey) throws -> (prekeys: [RV_DevicePrekey], keys: [EncryptionPublicKey : EncryptionPrivateKey])  {
        Crypto.ensureRandomness()
        var keys = [EncryptionPublicKey : EncryptionPrivateKey]()
        try (0..<count).forEach { _ in
            let privateKey = try EncryptionPrivateKey()
            keys[privateKey.publicKey] = privateKey
        }
        
        // Sign the keys and package them
        let preKeys: [RV_DevicePrekey] = keys.keys.map { publicKey in
            RV_DevicePrekey.with {
                let preKey = publicKey.rawRepresentation
                $0.preKey = preKey
                $0.signature = device.signature(for: preKey)
            }
        }
        return (preKeys, keys)
    }
    
    /**
     Upload new device prekeys.
     
     Device prekeys are needed for the creation of new topic keys, which in turn are used to establish a new topic.
     Device prekeys are random private keys, where the corresponding public key is signed with the device key
     and uploaded to the server. Any device of the user can then retrieve prekeys for all devices, encrypt a topic key
     with them, and upload the encryptions to the server.
     
     - Parameter count: The number of prekeys to upload.
     - Parameter completion: A closure called when the request is completed.
     - Parameter result: The number of uploaded prekeys, or an error.
     */
    public func uploadPreKeys(count: Int = 100, completion: @escaping (_ result: Result<Int, RendezvousError>) -> Void) throws {
        // Create the private pre keys
        let (preKeys, keys) = try Device.createPreKeys(count: count, for: devicePrivateKey)
        
        // Create the upload request
        let object = RV_DevicePrekeyUploadRequest.with {
            $0.publicKey = userKey.rawRepresentation
            $0.deviceKey = deviceKey.rawRepresentation
            $0.authToken = authToken
            $0.preKeys = preKeys
        }
        let data = try object.serializedData()
        
        upload(data, to: "device/prekeys", onSuccess: {
            // Save the uploaded prekeys
            self.preKeys.merge(keys, uniquingKeysWith: { a, _ in a })
            return count
        }, completion: completion)
    }
    
    /**
     Update the info about the existing devices of the user.
     - Parameter completion: A closure called with the result of the request.
     - Parameter error: An error, if the update failed.
     */
    public func updateUserInfo(completion: @escaping (_ error: RendezvousError?) -> Void) {
        download("user/prekeys", headers: authenticatedHeaders, process: { data in
            guard let object = try? RV_InternalUser(serializedData: data) else {
                throw RendezvousError.invalidServerData
            }
            try self.update(info: object)
        }, completion: completion)
    }
    
    /**
     Upload new topic keys by first downloading prekeys for all other devices.
    
     - Parameter count: The number of prekeys to create.
     - Parameter completion: The closure called with the result
     - Parameter result: The number of new topic keys, or an error.
     */
    public func uploadTopicKeys(count: Int = 20, completion: @escaping (_ result: Result<Int, RendezvousError>) -> Void) {
        // Create the headers
        var headers = authenticatedHeaders
        headers.add(count: count)
        
        // Make the request
        download("user/prekeys", headers: headers, transform: RV_DevicePreKeyBundle.init) { result in
            self.uploadTopicKeys(with: result, completion: completion)
        }
    }
    
    private func uploadTopicKeys(with result: Result<RV_DevicePreKeyBundle, RendezvousError>, completion: @escaping (Result<Int, RendezvousError>) -> Void) {
        switch result {
        case .failure(let error):
            completion(.failure(error))
        case .success(let object):
            uploadTopicKeys(with: object, completion: completion)
        }
    }
    
    private func uploadTopicKeys(with object: RV_DevicePreKeyBundle, completion: @escaping (Result<Int, RendezvousError>) -> Void) {
        guard object.keyCount > 0 else {
            completion(.success(0))
            return
        }
        catching(completion: completion) {
            let (topicKeys, messages) = try self.makeTopicKeys(fromPreKeys: object)
            let keys = topicKeys.map { $0.publicKeys.object }
            try self.upload(topicKeys: keys, messages: messages) { error in
                guard let e = error else {
                    topicKeys.forEach { self.topicKeys[$0.publicKeys.signatureKey] = $0 }
                    completion(.success(Int(object.keyCount)))
                    return
                }
                completion(.failure(e))
            }
        }
    }
    
    private func upload(topicKeys: [RV_TopicKey], messages: [RV_TopicKeyMessageList], completion: @escaping (RendezvousError?) -> Void) throws {
        
        let key = deviceKey.rawRepresentation
        let bundle = RV_TopicKeyBundle.with {
            $0.publicKey = userKey.rawRepresentation
            $0.deviceKey = key
            $0.authToken = authToken
            $0.topicKeys = topicKeys
            // Remove all messages which would go to the sending device
            $0.messages = messages.filter { $0.deviceKey != key }
        }
        let data = try bundle.serializedData()
        
        let url = self.url.appendingPathComponent("user/topickeys")
        AF.upload(data, to: url).response { resp in
            guard let response = resp.response else {
                completion(.noResponse)
                return
            }
            guard response.statusCode == 200 else {
                let error = RendezvousError(status: response.statusCode)
                completion(error)
                return
            }
            completion(nil)
        }
    }
    
    func getTopicKey(for user: SigningPublicKey, completion: @escaping (Result<Topic.Key, RendezvousError>) -> Void) {
        
        var headers = authenticatedHeaders
        headers.add(receiverKey: user)
        
        let url = self.url.appendingPathComponent("user/topickey")
        AF.request(url, headers: headers).responseData { resp in
            guard let response = resp.response else {
                completion(.failure(.noResponse))
                return
            }
            guard response.statusCode == 200 else {
                let error = RendezvousError(status: response.statusCode)
                completion(.failure(error))
                return
            }
            
            guard let data = resp.data else {
                    completion(.failure(.noResponse))
                    return
            }
            do {
                let key = try Topic.Key(data: data, userKey: user)
                completion(.success(key))
            } catch {
                let e = error as! RendezvousError
                completion(.failure(e))
            }
        }
    }
    
    func getTopicKeys(for users: [SigningPublicKey], completion: @escaping (Result<[Topic.Key], RendezvousError>) -> Void) {
        let request = RV_TopicKeyRequest.with {
            $0.publicKey = userKey.rawRepresentation
            $0.deviceKey = deviceKey.rawRepresentation
            $0.authToken = authToken
            $0.users = users.map { $0.rawRepresentation }
        }
        let data = try! request.serializedData()
        upload(data, to: "users/topickey", transform: Topic.Key.from, completion: completion)
    }
    
    /**
     Create a new topic.
     
     - Parameter members:The public keys of the members and their roles.
     - Parameter completion: A closure called with the result.
     - Parameter result: The resulting topic, or an error
     */
    public func createTopic(with members: [SigningPublicKey : Topic.Role], completion: @escaping (_ result: Result<Topic, RendezvousError>) -> Void) {
        getTopicKeys(for: Array(members.keys)) { resp in
            switch resp {
            case .failure(let error):
                completion(.failure(error))
            case .success(let keys):
                self.continueTopicCreation(with: keys, members: members, completion: completion)
            }
        }
    }
    
    private func continueTopicCreation(with keys: [Topic.Key], members: [SigningPublicKey : Topic.Role], completion: @escaping (Result<Topic, RendezvousError>) -> Void) {
        // Here we ignore all members which don't have a topic key at the moment.
        let data = keys.compactMap { key -> (role: Topic.Role, key: Topic.Key)? in
            // Check that topic key belongs to a member of the group
            guard let role = members[key.userKey] else {
                return nil
            }
            return (role, key)
        }
        do {
            try createTopic(with: data, completion: completion)
        } catch let error as RendezvousError {
            completion(.failure(error))
        } catch {
            completion(.failure(.unknownError))
        }
    }
    
    func createTopic(with members: [(role: Topic.Role, key: Topic.Key)] = [], completion: @escaping (Result<Topic, RendezvousError>) -> Void) throws {
        guard let topicKey = topicKeys.popFirst()?.value else {
            throw RendezvousError.invalidRequest
        }
        let messageKey = try SymmetricKey(size: .bits256)
        let now = Date.secondsNow
        let roles = [(role: .admin, key: topicKey.publicKeys)] + members
        var topic = try RV_Topic.with { t in
            t.topicID = try Crypto.newTopicId()
            t.creationTime = now
            t.indexOfMessageCreator = 0
            // Encrypt the message key to each user with their topic key
            t.members = try roles.map { role, key in
                try key.encrypt(messageKey.rawBytes, role: role) }
            t.timestamp = now
        }
        
        try topic.sign(with: topicKey.signing)
        let data = try topic.serializedData()
        
        let result = try Topic(selfCreatedTopic: topic, withTopicKey: topicKey, messageKey: messageKey)
        upload(data, to: "topic/create", headers: authenticatedHeaders, onSuccess: { () -> Topic in
            result
        }, completion: completion)
    }
    
    /**
     Upload a new message.
     
     - Parameter message: The message data.
     - Parameter metadata: The metadata of the message.
     - Parameter topic: The topic to send the message to.
     - Parameter completion: A closure called with the resulting topic chain state or an error.
     - Parameter result: The topic chain state after the message, or an error.
     */
    public func upload(message: Data, metadata: Data, to topic: Topic, completion: @escaping (_ result: Result<Chain, RendezvousError>) -> Void) throws {
        // Check that user is part of the group, and can write
        guard let index = topic.members.firstIndex(where: { $0.userKey == userKey }),
            topic.members[index].role != .observer else {
                throw RendezvousError.invalidRequest
        }
        // Encrypt the data
        let encryptedMessage = try AES.GCM.seal(message, using: topic.messageKey)
        let encryptedMetadata = try AES.GCM.seal(metadata, using: topic.messageKey).combined
        let hash = SHA2(variant: .sha256).calculate(for: encryptedMessage.ciphertext.bytes)
        
        // Create the message
        var request = RV_TopicMessageUpload.with {
            $0.deviceKey = deviceKey.rawRepresentation
            $0.authToken = authToken
            $0.topicID = topic.id
            $0.file = encryptedMessage.ciphertext
            $0.message = .with { message in
                message.indexInMemberList = UInt32(index)
                message.id = encryptedMessage.nonce.rawRepresentation
                message.hash = Data(hash)
                message.tag = encryptedMessage.tag
                message.metadata = encryptedMetadata
            }
        }
        
        // Sign the message and serialize
        try request.message.sign(with: topic.signatureKey)
        let data = try request.serializedData()
        upload(data, to: "topic/message", transform: { data -> Chain in
            do {
                let object = try RV_TopicState.ChainState(serializedData: data)
                return Chain(object: object)
            } catch {
                throw RendezvousError.invalidServerData
            }
        }, completion: completion)
    }
    
    public func getMessages(completion: @escaping (RendezvousError?) -> Void) {
        
        download("device/messages", headers: authenticatedHeaders, process: { data in
            let object = try RV_DeviceDownload(serializedData: data)
            
            if object.hasUserInfo {
                try self.update(info: object.userInfo)
            }
            try self.decrypt(topicKeyMessages: object.topicKeyMessages)
            try self.received(topicUpdates: object.topicUpdates)
            try self.decrypt(messages: object.messages)
            
        }, completion: completion)
    }
    
    private func decrypt(topicKeyMessages messages: [RV_TopicKeyMessage]) throws {
        try messages.forEach(decrypt)
    }
    
    private func decrypt(topicKeyMessage message: RV_TopicKeyMessage) throws {
        
        // Find the right private key
        let preKey = try EncryptionPublicKey(rawRepresentation: message.devicePreKey)
        guard let privateKey = preKeys[preKey] else {
            // No prekey found
            throw RendezvousError.unknownError
        }
        
        let topicKey = try Topic.Keys(message: message, preKey: privateKey, userKey: userKey)
        topicKeys[topicKey.publicKeys.signatureKey] = topicKey
    }
    
    private func received(topicUpdates: [RV_Topic]) throws {
        try topicUpdates.forEach(received)
    }
    
    private func received(topicUpdate: RV_Topic) throws {
        guard let oldInfo = topics[topicUpdate.topicID] else {
            // Topic is new
            try process(newTopic: topicUpdate)
            return
        }
        guard topicUpdate.timestamp > oldInfo.modified.seconds else {
            // Topic info is outdated
            return
        }
        #warning("Implement topic update")
    }
    
    private func process(newTopic topic: RV_Topic) throws {
        let ownKey = userKey.rawRepresentation
        guard let keyData = topic.members.first(where: { $0.info.userKey == ownKey })?.signatureKey else {
            throw RendezvousError.unknownError
        }
        let signatureKey = try SigningPublicKey(rawRepresentation: keyData)
        guard let keys = topicKeys[signatureKey] else {
            throw RendezvousError.unknownError
        }
        let topic = try Topic(newTopic: topic, withTopicKey: keys)
        
        topics[topic.id] = topic
        delegate?.device(addedTopic: topic)
    }
    
    private func decrypt(messages: [RV_DeviceDownload.Message]) throws {
        print("Received \(messages.count) messages")
        try messages.forEach(decrypt)
    }
    
    private func decrypt(message: RV_DeviceDownload.Message) throws {
        guard let topic = topics[message.topicID] else {
            throw RendezvousError.unknownError
        }
        
        // Get the sender
        let index = Int(message.content.indexInMemberList)
        guard index < topic.members.count else {
            throw RendezvousError.unknownError
        }
        let sender = topic.members[index]
        
        // Verify the message
        try message.content.verifySignature(with: sender.signatureKey)
        
        // Decrypt the metadata
        let encryptedMetadata = try AES.GCM.SealedBox(combined: message.content.metadata)
        let metadata = try AES.GCM.open(encryptedMetadata, using: topic.messageKey)
        
        let message = Message(object: message, metadata: metadata, sender: sender.userKey)
        // See if the topic state can be verified.
        guard message.index == topic.verifiedIndex else {
            // Message is not the next expected one, so mark as pending
            // and download other messages
            topic.unverifiedMessages.append(message)
            delegate?.device(receivedMessage: message, in: topic, verified: false)
            return
        }
        
        // Calculate the new output
        let output = Crypto.SHA256(topic.verifiedOutput + message.signature)
        guard output == message.output else {
            // Invalid chain. This implies an inconsistency in the message chain,
            // which could indicate that the server is attempting to tamper with
            // the messages
            delegate?.device(foundInvalidChain: message.index, in: topic)
            return
        }
        topic.verifiedIndex = message.index
        topic.verifiedOutput = output
        delegate?.device(receivedMessage: message, in: topic, verified: true)
    }
}
