//
//  DeviceConnection.swift
//  Alamofire
//
//  Created by Christoph on 10.01.20.
//

import Foundation
import Alamofire
import CryptoKit

public protocol DeviceDelegate: class {
    
    func user(changedDevice device: DeviceInfo)
    
    func user(addedDevice device: DeviceInfo)
    
    func user(removedDevice device: DeviceInfo)
    
    func device(addedTopic topic: Topic)
    
    func device(receivedMessage message: Message, in topic: Topic, verified: Bool)
    
    func device(foundInvalidChain index: Int, in topic: Topic)
}

public final class Device: Server {

    /// The private identity key of the user
    let userPrivateKey: SigningPrivateKey
    
    /// The public identity key of the user
    let userKey: SigningPublicKey
    
    /// The private key of the device
    let devicePrivateKey: SigningPrivateKey
    
    /// The public key of the device
    let deviceKey: SigningPublicKey
    
    /// Info about the user and the devices
    private var object: RV_InternalUser
    
    let authToken: Data
    
    var preKeys = [EncryptionKeyPair]()
    
    var topicKeys = [Topic.Keys]()
    
    var topics = [Data : Topic]()
    
    public weak var delegate: DeviceDelegate?
    
    // MARK: Computed properties
    
    public var created: Date {
        .init(seconds: object.creationTime)
    }
    
    public var name: String {
        object.name
    }
    
    public var changed: Date {
        .init(seconds: object.timestamp)
    }
    
    public var devices: [DeviceInfo] {
        try! object.devices.map(DeviceInfo.init)
    }
    
    // MARK: Initialization
    
    /**
     Create a device.
     */
    init(url: URL, userKey: SigningPrivateKey, info: RV_InternalUser,  deviceKey: SigningPrivateKey, authToken: Data) {
        self.devicePrivateKey = deviceKey
        self.deviceKey = deviceKey.publicKey
        self.authToken = authToken
        self.userPrivateKey = userKey
        self.userKey = userKey.publicKey
        self.object = info
        super.init(url: url)
        
    }
    
    // MARK: Public functions
    
    /**
     Upload new device prekeys.
     
     Device prekeys are needed for the creation of new topic keys, which in turn are used to establish a new topic.
     Device prekeys are random private keys, where the corresponding public key is signed with the device key
     and uploaded to the server. Any device of the user can then retrieve prekeys for all devices, encrypt a topic key
     with them, and upload the encryptions to the server.
     
     - Parameter count: The number of prekeys to upload.
     - Parameter onError: A closure called with an error if the request fails.
     - Parameter onSuccess: A closure called if the request succeeds.
     */
    public func uploadPreKeys(count: Int = 100, onError: @escaping RendezvousErrorHandler, onSuccess: @escaping () -> Void) {
        catching(onError: onError) {
            // Create the private pre keys
            let (publicPreKeys, privatePreKeys) = try Crypto.createPreKeys(count: count, for: devicePrivateKey)
            
            // Create the upload request
            let object = RV_DevicePrekeyUploadRequest.with {
                $0.publicKey = userKey.rawRepresentation
                $0.deviceKey = deviceKey.rawRepresentation
                $0.authToken = authToken
                $0.preKeys = publicPreKeys
            }
            let data = try object.serializedData()
            upload(data, to: "device/prekeys", onError: onError) {
                // Save the uploaded prekeys
                self.preKeys.append(contentsOf: privatePreKeys)
                onSuccess()
            }
        }
    }
    
    /**
     Update the info about the existing devices of the user.
     
     - Parameter onError: A closure called with an error if the request fails.
     - Parameter onSuccess: A closure called if the request succeeds.
     */
    public func updateUserInfo(onError: @escaping RendezvousErrorHandler, onSuccess: @escaping () -> Void) {
        download("user/prekeys", headers: authenticatedHeaders, onError: onError) { data in
            guard let object = try? RV_InternalUser(serializedData: data) else {
                throw RendezvousError.invalidServerData
            }
            try self.update(info: object)
        }
    }
    
    /**
     Upload new topic keys by first downloading prekeys for all other devices.
    
     - Parameter count: The number of prekeys to create.
     - Parameter onError: A closure called with an error if the request fails.
     - Parameter onSuccess: A closure called if the request succeeds.
     - Parameter uploadedKeys: The number of uploaded topic keys.
     */
    public func uploadTopicKeys(count: Int = 20, onError: @escaping RendezvousErrorHandler, onSuccess: @escaping (_ uploadedKeys: Int) -> Void) {
        // Create the headers
        var headers = authenticatedHeaders
        headers.add(count: count)
        
        // Make the request to download prekeys for each user
        download("user/prekeys", headers: headers, onError: onError) { data in
            guard let object = try? RV_DevicePreKeyBundle(serializedData: data) else {
                throw RendezvousError.invalidServerData
            }
            guard object.keyCount > 0 else {
                onSuccess(0)
                return
            }
            let (topicKeys, messages) = try self.makeTopicKeys(fromPreKeys: object)
            let keys = topicKeys.map { $0.publicKeys.object }
            let key = self.deviceKey.rawRepresentation
            let bundle = RV_TopicKeyBundle.with {
                $0.publicKey = self.userKey.rawRepresentation
                $0.deviceKey = key
                $0.authToken = self.authToken
                $0.topicKeys = keys
                // Remove all messages which would go to the sending device
                $0.messages = messages.filter { $0.deviceKey != key }
            }
            let data = try bundle.serializedData()
            
            // Make the request to upload the topic keys
            self.upload(data, to: "user/topickeys", onError: onError) {
                self.topicKeys.append(contentsOf: topicKeys)
                onSuccess(topicKeys.count)
            }
        }
    }
    
    /**
     Create a new topic.
     
     - Parameter members:The public keys of the members and their roles.
     - Parameter onError: A closure called with an error if the request fails.
     - Parameter onSuccess: A closure called with the topic if the request succeeds.
     - Parameter topic: The resulting topic
     */
    public func createTopic(with members: [(SigningPublicKey, Topic.Role)], onError: @escaping RendezvousErrorHandler, onSuccess: @escaping (_ topic: Topic) -> Void) {
        
        let request = RV_TopicKeyRequest.with {
            $0.publicKey = userKey.rawRepresentation
            $0.deviceKey = deviceKey.rawRepresentation
            $0.authToken = authToken
            $0.users = members.map { $0.0.rawRepresentation }
        }
        guard let data = try? request.serializedData() else {
            onError(.serializationFailed)
            return
        }
        
        // First download the topic keys for each member
        upload(data, to: "users/topickey", onError: onError) { data in
            let keys = try Topic.Key.from(data: data)
            // Here we ignore all members which don't have a topic key at the moment.
            let memberData = keys.compactMap { key -> (role: Topic.Role, key: Topic.Key)? in
                // Check that topic key belongs to a member of the group
                guard let role = members.first(where: { $0.0 == key.userKey })?.1 else {
                    return nil
                }
                return (role, key)
            }
            guard let topicKey = self.topicKeys.popLast() else {
                throw RendezvousError.invalidRequest
            }
            let messageKey = Crypto.newMessageKey()
            let now = Date.secondsNow
            let roles = [(role: .admin, key: topicKey.publicKeys)] + memberData
            var topic = try RV_Topic.with { t in
                t.topicID = try Crypto.newTopicId()
                t.creationTime = now
                t.indexOfMessageCreator = 0
                // Encrypt the message key to each user with their topic key
                t.members = try roles.map { role, key in
                    try key.encrypt(messageKey.rawRepresentation, role: role) }
                t.timestamp = now
            }
            
            try topic.sign(with: topicKey.signing)
            let data = try topic.serializedData()
            
            let result = try Topic(selfCreatedTopic: topic, withTopicKey: topicKey, messageKey: messageKey)
            self.upload(data, to: "topic/create", headers: self.authenticatedHeaders, onError: onError) {
                onSuccess(result)
            }
        }
    }
    
    /**
     Upload a new message.
     
     - Parameter message: The message data.
     - Parameter metadata: The metadata of the message.
     - Parameter topic: The topic to send the message to.
     - Parameter onError: A closure called with an error if the request fails.
     - Parameter onSuccess: A closure called with the resulting message chain if the request succeeds.
     - Parameter chain: The topic chain state after the message.
     */
    public func upload(message: Data, metadata: Data, to topic: Topic, onError: @escaping RendezvousErrorHandler, onSuccess: @escaping (_ chain: Chain) -> Void) {
        catching(onError: onError) {
            // Check that user is part of the group, and can write
            guard let index = topic.members.firstIndex(where: { $0.userKey == userKey }),
                topic.members[index].role != .observer else {
                    throw RendezvousError.invalidRequest
            }
            // Encrypt the data
            let encryptedMessage = try AES.GCM.seal(message, using: topic.messageKey)
            let encryptedMetadata = try AES.GCM.seal(metadata, using: topic.messageKey).combined!
            let hash = Crypto.sha256(of: encryptedMessage.ciphertext)
            
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
            upload(data, to: "topic/message", onError: onError) { data in
                guard let object = try? RV_TopicState.ChainState(serializedData: data) else {
                    onError(.invalidServerData)
                    return
                }
                onSuccess(Chain(object: object))
            }
        }
    }
    
    /**
     Receive all messages for a device.

     The received data is handled by the class, and notifications to received data can be observed by the delegate.
     - Parameter onError: A closure called if the request fails.
     - Parameter onSuccess: A closure called if the request succeeds.
     */
    public func getMessages(onError: @escaping RendezvousErrorHandler, onSuccess: @escaping () -> Void) {
        
        download("device/messages", headers: authenticatedHeaders, onError: onError) { data in
            let object = try RV_DeviceDownload(serializedData: data)
            
            if object.hasUserInfo {
                try self.update(info: object.userInfo)
            }
            try self.decrypt(topicKeyMessages: object.topicKeyMessages)
            try self.received(topicUpdates: object.topicUpdates)
            try self.decrypt(messages: object.messages)
            onSuccess()
        }
    }
    
    // MARK: Notifications
    
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
    
    // MARK: Requests
    
    private var authenticatedHeaders: HTTPHeaders {
        var headers: HTTPHeaders = []
        headers.add(userKey: userKey)
        headers.add(deviceKey: deviceKey)
        headers.add(authToken: authToken)
        return headers
    }
    
    /**
     Get a topic key for a user.
     
     - Parameter onError: A closure called with an error if the request fails.
     - Parameter onSuccess: A closure called with the topic key if the request succeeds.
     */
    func getTopicKey(for user: SigningPublicKey, onError: @escaping RendezvousErrorHandler, onSuccess: @escaping (Topic.Key) -> Void) {
        
        var headers = authenticatedHeaders
        headers.add(receiverKey: user)
        
        download("user/topickey", headers: headers, onError: onError) { data in
            let key = try Topic.Key(data: data, userKey: user)
            onSuccess(key)
        }
    }

    // MARK: User info
    
    func update(info: RV_InternalUser) throws {
        guard info.timestamp > object.timestamp else {
            throw RendezvousError.requestOutdated
        }
        let signatureKey = try SigningPublicKey(rawRepresentation: object.publicKey)
        try info.isFreshAndSigned(with: signatureKey)
        
        guard info.publicKey == object.publicKey else {
            throw RendezvousError.invalidServerData
        }
        guard info.name == object.name,
            info.creationTime == object.creationTime,
            info.devices.isSorted(by: { $0.creationTime }) else {
                // If we reach this point, then one of the users devices messed up
                // by creating an invalid info, and the server somehow didn't catch it.
                throw RendezvousError.invalidServerData
        }
        guard let delegate = delegate else {
            self.object = info
            return
        }

        // Find new and changed devices
        for device in info.devices {
            guard let old = object.devices.first(where: { $0.deviceKey == device.deviceKey }) else {
                // Device is new
                delegate.user(addedDevice: try DeviceInfo(object: device))
                continue
            }
            if old != device {
                // Device has changed
                delegate.user(changedDevice: try DeviceInfo(object: device))
            }
        }
        // Find deleted devices {
        for device in object.devices {
            if !info.devices.contains(where: { $0.deviceKey == device.deviceKey }) {
                delegate.user(removedDevice: try DeviceInfo(object: device))
            }
        }

        self.object = info
    }
    
    // MARK: Keys

    func makeTopicKeys(fromPreKeys preKeys: RV_DevicePreKeyBundle) throws -> (topicKeys: [Topic.Keys], messages: [RV_TopicKeyMessageList]) {
        var existingDevices = Set(object.devices.map { $0.deviceKey })
        let count = Int(preKeys.keyCount)
        
        // Create the topic keys
        let topicKeys = try Crypto.createTopicKeys(count: count, for: userPrivateKey)
        
        // Create the resulting message dictionary
        var messages = [Data : RV_TopicKeyMessageList]()

        for list in preKeys.devices {
            // Check that the device exists in the list of devices
            guard let _ = existingDevices.remove(list.deviceKey) else {
                throw RendezvousError.invalidRequest
            }
            // Check that the number of prekeys matches
            guard list.prekeys.count == count else {
               throw RendezvousError.invalidRequest
            }

            let device = try SigningPublicKey(rawRepresentation: list.deviceKey)
            messages[list.deviceKey] = try .with { item in
                item.deviceKey = list.deviceKey
                item.messages = try list.prekeys.enumerated().map { index, key in
                    // Check that the signatures are valid, and that public keys match.
                    guard device.isValidSignature(key.signature, for: key.preKey) else {
                        throw RendezvousError.invalidRequest
                    }
                    return try topicKeys[index].message(withPrekey: key)
                }
            }
        }
        
        // Check that no prekeys for a device are missing
        guard existingDevices.isEmpty else {
            throw RendezvousError.invalidRequest
        }
        
        return (topicKeys, Array(messages.values))
    }
    
    // MARK: Handling received data
    
    private func decrypt(topicKeyMessages messages: [RV_TopicKeyMessage]) throws {
        try messages.forEach(decrypt)
    }
    
    private func decrypt(topicKeyMessage message: RV_TopicKeyMessage) throws {
        
        // Find the right private key
        let preKey = try EncryptionPublicKey(rawRepresentation: message.devicePreKey)
        guard let privateKey = preKeys.first(where: { $0.public == preKey })?.private else {
            // No prekey found
            throw RendezvousError.unknownError
        }
        
        let topicKey = try Topic.Keys(message: message, preKey: privateKey, userKey: userKey)
        topicKeys.append(topicKey)
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
        guard let keys = topicKeys.first(where: { $0.publicKeys.signatureKey == signatureKey }) else {
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
        let output = Crypto.sha256(of: topic.verifiedOutput + message.signature)
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
