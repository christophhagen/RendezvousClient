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
    
    func device(receivedMessage message: Update, in topic: Topic, verified: Bool)
    
    func device(receivedChainState chainState: UInt32, for topic: TopicID, from sender: SigningPublicKey)
    
    func device(foundInvalidChain index: UInt32, in topic: Topic)
}

public final class Device: Server {
    
    /// The private identity key of the user
    let userPrivateKey: SigningPrivateKey
    
    /// The public identity key of the user
    public let userKey: SigningPublicKey
    
    /// The private key of the device
    let devicePrivateKey: SigningPrivateKey
    
    /// The public key of the device
    public let deviceKey: SigningPublicKey
    
    /// Info about the user and the devices
    private var userInfo: RV_InternalUser
    
    /// The authentication token for the server
    let authToken: AuthToken
    
    /// The list of unused prekeys
    var preKeys: [EncryptionKeyPair]
    
    /// The list of unused topic keys
    var topicKeys: [Topic.Keys]
    
    /// All currently existing topics with their info, indexed by their id
    var topics: [Data : Topic]
    
    /// The delegate receiving events
    public weak var delegate: DeviceDelegate?
    
    // MARK: Computed properties
    
    public var created: Date {
        .init(seconds: userInfo.creationTime)
    }
    
    public var name: String {
        userInfo.name
    }
    
    public var changed: Date {
        .init(seconds: userInfo.timestamp)
    }
    
    public var devices: [DeviceInfo] {
        try! userInfo.devices.map(DeviceInfo.init)
    }
    
    /// The public keys of all user devices except the local one.
    var otherDevices: Set<DeviceKey> {
        let key = deviceKey.rawRepresentation
        return Set(userInfo.devices.filter({ $0.deviceKey != key }).map { $0.deviceKey })
    }
    
    // MARK: Initialization
    
    /**
     Create a device.
     */
    init(url: URL, appId: String, userKey: SigningPrivateKey, info: RV_InternalUser,  deviceKey: SigningPrivateKey, authToken: Data) {
        self.devicePrivateKey = deviceKey
        self.deviceKey = deviceKey.publicKey
        self.authToken = authToken
        self.userPrivateKey = userKey
        self.userKey = userKey.publicKey
        self.userInfo = info
        self.preKeys = []
        self.topicKeys = []
        self.topics = [:]
        super.init(url: url, appId: appId)
        
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
        headers.add(appId: appId)
        
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
                $0.application = self.appId
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
    public func createTopic(with members: [(SigningPublicKey, Topic.Member.Role)], onError: @escaping RendezvousErrorHandler, onSuccess: @escaping (_ topic: Topic) -> Void) {
        
        let request = RV_TopicKeyRequest.with {
            $0.publicKey = userKey.rawRepresentation
            $0.deviceKey = deviceKey.rawRepresentation
            $0.authToken = authToken
            $0.users = members.map { $0.0.rawRepresentation }
            $0.application = appId
        }
        guard let data = try? request.serializedData() else {
            onError(.serializationFailed)
            return
        }
        
        // First download the topic keys for each member
        upload(data, to: "users/topickey", onError: onError) { data in
            let keys = try Topic.Key.from(data: data)
            // Here we ignore all members which don't have a topic key at the moment.
            let memberData = keys.compactMap { key -> (role: Topic.Member.Role, key: Topic.Key)? in
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
                t.application = self.appId
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
     Generate a new message id.
     */
    public func newMessageId() -> MessageID {
        AES.GCM.Nonce().rawRepresentation
    }
    
    /**
    Upload a new message.
    
    - Parameter data: The message data.
    - Parameter metadata: The metadata of the message.
    - Parameter topic: The topic to send the message to.
    - Parameter onError: A closure called with an error if the request fails.
    - Parameter onSuccess: A closure called with the resulting message chain if the request succeeds.
    - Parameter update: The topic update resulting from the upload
    */
    public func upload(data: Data, metadata: Data, to topic: Topic, onError: @escaping RendezvousErrorHandler, onSuccess: @escaping (_ update: Update) -> Void) {
        let id = newMessageId()
        upload(file: (id, data), metadata: metadata, to: topic, onError: onError, onSuccess: onSuccess)

    }
    
    /**
     Upload a new update with a file.
     
     - Parameter file: The file to upload, with an id and the file data.
     - Parameter metadata: The metadata of the update.
     - Parameter topic: The topic to send the update to.
     - Parameter onError: A closure called with an error if the request fails.
     - Parameter onSuccess: A closure called with the resulting message chain if the request succeeds.
     - Parameter update: The topic update resulting from the upload
     */
    public func upload(file: (id: MessageID, data: Data), metadata: Data, to topic: Topic, onError: @escaping RendezvousErrorHandler, onSuccess: @escaping (_ update: Update) -> Void) {
        upload(files: [file], metadata: metadata, to: topic, onError: onError, onSuccess: onSuccess)
    }

    /**
    Upload a new update with additional files.
    
    - Parameter files: The files to upload, each with an id and the file data.
    - Parameter metadata: The metadata of the update.
    - Parameter topic: The topic to send the update to.
    - Parameter onError: A closure called with an error if the request fails.
    - Parameter onSuccess: A closure called with the resulting message chain if the request succeeds.
    - Parameter update: The topic update resulting from the upload
    */
    public func upload(files: [(id: MessageID, data: Data)] = [], metadata: Data, to topic: Topic, onError: @escaping RendezvousErrorHandler, onSuccess: @escaping (_ update: Update) -> Void) {
        
        catching(onError: onError) {
            
            // Check that user is part of the group, and can write
            guard let index = topic.members.firstIndex(where: { $0.userKey == userKey }),
                topic.members[index].role != .observer else {
                    throw RendezvousError.invalidRequest
            }
            
            // Encrypt the data
            let files = try encrypt(files, key: topic.messageKey)
            let encryptedMetadata = try AES.GCM.seal(metadata, using: topic.messageKey).combined!
            
            // Create the message
            var request = RV_TopicUpdateUpload.with {
                $0.deviceKey = deviceKey.rawRepresentation
                $0.authToken = authToken
                $0.topicID = topic.id
                $0.files = files.map { file in
                    .with {
                        $0.id = file.file.id
                        $0.data = file.data
                    }
                }
                $0.update = .with { update in
                    update.indexInMemberList = UInt32(index)
                    update.metadata = encryptedMetadata
                    update.files = files.map { $0.file.object }
                }
            }
            
            // Sign the message and serialize
            try request.update.sign(with: topic.signatureKey)
            let requestData = try request.serializedData()
            upload(requestData, to: "topic/message", onError: onError) { data in
                guard let object = try? RV_TopicState.ChainState(serializedData: data) else {
                    onError(.invalidServerData)
                    return
                }
                let update = Update(
                    update: request.update,
                    chain: object,
                    sender: self.userKey)
                
                onSuccess(update)
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
            self.process(receipts: object.receipts)
            onSuccess()
        }
    }
    
    /**
    Download the file data of a message.
    
    - Parameter message: The message to download.
    - Parameter topic: The topic id of the message.
    - Parameter onError: A closure called if the request fails.
    - Parameter onSuccess: A closure called with the file data if the request succeeds.
    */
    public func getFile(_ file: Update.File, in topic: TopicID, onError: @escaping RendezvousErrorHandler, onSuccess: @escaping (Data) -> Void) {
        guard let topic = self.topics[topic] else {
            onError(.invalidRequest)
            return
        }
        getFile(file, in: topic, onError: onError, onSuccess: onSuccess)
    }
    
    /**
     Download the file data of a message.
     
     - Parameter message: The message to download.
     - Parameter topic: The topic of the message.
     - Parameter onError: A closure called if the request fails.
     - Parameter onSuccess: A closure called with the file data if the request succeeds.
     */
    public func getFile(_ file: Update.File, in topic: Topic, onError: @escaping RendezvousErrorHandler, onSuccess: @escaping (Data) -> Void) {
        
        let path = "files/\(topic.id.url)/\(file.id.url)"
        download(path, headers: authenticatedHeaders, onError: onError) { data in
            guard SHA256.hash(data: data) == file.hash else {
                throw RendezvousError.invalidFile
            }
            do {
                let nonce = try AES.GCM.Nonce(data: file.id)
                let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: data, tag: file.tag)
                let decrypted = try AES.GCM.open(box, using: topic.messageKey)
                onSuccess(decrypted)
            } catch {
                onError(.invalidFile)
            }
        }
    }
    
    public func receivedMessageFromPush(_ data: String) throws {
        guard let data = Data(base64Encoded: data),
            let message = try? RV_DeviceDownload.Message(serializedData: data) else {
                throw RendezvousError.invalidServerData
        }
        try decrypt(message: message)
    }
    
    public func receivedTopicFromPush(_ data: String) throws {
        guard let data = Data(base64Encoded: data),
            let topic = try? RV_Topic(serializedData: data) else {
                throw RendezvousError.invalidServerData
        }
        try process(newTopic: topic)
    }
    
    public func receivedReceiptsFromPush(_ data: String) throws {
        guard let data = Data(base64Encoded: data),
            let topic = try? RV_DeviceDownload.Receipt(serializedData: data) else {
                throw RendezvousError.invalidServerData
        }
        self.process(receipt: topic)
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
        headers.add(appId: appId)
        
        download("user/topickey", headers: headers, onError: onError) { data in
            let key = try Topic.Key(data: data, userKey: user)
            onSuccess(key)
        }
    }

    // MARK: User info
    
    func update(info: RV_InternalUser) throws {
        guard info.timestamp > userInfo.timestamp else {
            throw RendezvousError.requestOutdated
        }
        let signatureKey = try SigningPublicKey(rawRepresentation: userInfo.publicKey)
        try info.isFreshAndSigned(with: signatureKey)
        
        guard info.publicKey == userInfo.publicKey else {
            throw RendezvousError.invalidServerData
        }
        guard info.name == userInfo.name,
            info.creationTime == userInfo.creationTime,
            info.devices.isSorted(by: { $0.creationTime }) else {
                // If we reach this point, then one of the users devices messed up
                // by creating an invalid info, and the server somehow didn't catch it.
                throw RendezvousError.invalidServerData
        }
        guard let delegate = delegate else {
            self.userInfo = info
            return
        }

        // Find new and changed devices
        for device in info.devices {
            guard let old = userInfo.devices.first(where: { $0.deviceKey == device.deviceKey }) else {
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
        for device in userInfo.devices {
            if !info.devices.contains(where: { $0.deviceKey == device.deviceKey }) {
                delegate.user(removedDevice: try DeviceInfo(object: device))
            }
        }

        self.userInfo = info
    }
    
    // MARK: Keys

    func makeTopicKeys(fromPreKeys preKeys: RV_DevicePreKeyBundle) throws -> (topicKeys: [Topic.Keys], messages: [RV_TopicKeyMessageList]) {
        let count = Int(preKeys.keyCount)
        
        // Create the topic keys
        let topicKeys = try Crypto.createTopicKeys(count: count, for: userPrivateKey)
        
        // Create the resulting message dictionary
        var messages = [Data : RV_TopicKeyMessageList]()

        var existingDevices = otherDevices
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
    
    private func encrypt(_ files: [(id: MessageID, data: Data)], key: SymmetricKey) throws -> [(file: Update.File, data: Data)] {
        
        return try files.map { file in
            // Check that the message id is valid
            guard file.id.count == Constants.messageIdLength else {
                throw RendezvousError.invalidFile
            }
            
            let nonce = try AES.GCM.Nonce(data: file.id)
            let box = try AES.GCM.seal(file.data, using: key, nonce: nonce)
            let hash = Crypto.sha256(of: box.ciphertext)
            let f = Update.File(id: file.id, tag: box.tag, hash: hash)
            return (f, file.data)
        }
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
        
        let message = Update(object: message, metadata: metadata, sender: sender.userKey)
        // See if the topic state can be verified.
        guard message.chainIndex == topic.chainIndex + 1 else {
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
            delegate?.device(foundInvalidChain: message.chainIndex, in: topic)
            return
        }
        topic.chainIndex = message.chainIndex
        topic.verifiedOutput = output
        delegate?.device(receivedMessage: message, in: topic, verified: true)
    }
    
    private func process(receipts: [RV_DeviceDownload.Receipt]) {
        receipts.forEach(process)
    }
    
    private func process(receipt: RV_DeviceDownload.Receipt) {
        guard let sender = try? SigningPublicKey(rawRepresentation: receipt.sender) else {
            return
        }
        for topic in receipt.receipts {
            delegate?.device(receivedChainState: topic.index, for: topic.id, from: sender)
        }
    }
    
    // MARK: Serialization
    
    var object: RV_ClientData {
        return .with {
            $0.userPrivateKey = userPrivateKey.rawRepresentation
            $0.devicePrivateKey = devicePrivateKey.rawRepresentation
            $0.devicePublicKey = deviceKey.rawRepresentation
            $0.userInfo = userInfo
            $0.authToken = authToken
            $0.prekeys = preKeys.map { key in
                RV_ClientData.KeyPair.with { pair in
                    pair.privateKey = key.private.rawRepresentation
                    pair.publicKey = key.public.rawRepresentation
                }
            }
            $0.topicKeys = topicKeys.map { $0.object }
            $0.topics = topics.values.map { $0.object }
        }
    }
    
    /// The serialized data of the device, including all topics and keys.
    public var data: Data? {
        return try? object.serializedData()
    }
    
    /**
     Create the device from serialized data.
     */
    public convenience init(data: Data) throws {
        let object = try RV_ClientData(serializedData: data)
        try self.init(object: object)
    }
    
    init(object: RV_ClientData) throws {
        self.userPrivateKey = try SigningPrivateKey(rawRepresentation: object.userPrivateKey)
        let userKey =  try SigningPublicKey(rawRepresentation: object.userInfo.publicKey)
        self.userKey = userKey
        self.devicePrivateKey = try SigningPrivateKey(rawRepresentation: object.devicePrivateKey)
        self.deviceKey = try SigningPublicKey(rawRepresentation: object.devicePublicKey)
        self.userInfo = object.userInfo
        self.authToken = object.authToken
        guard let url = URL(string: object.serverURL) else {
            throw RendezvousError.serializationFailed
        }
        self.preKeys = try object.prekeys.map { key in
            let priv = try EncryptionPrivateKey(rawRepresentation: key.privateKey)
            let pub = try EncryptionPublicKey(rawRepresentation: key.publicKey)
            return (priv, pub)
        }
        self.topicKeys = try object.topicKeys.map {
            try Topic.Keys(object: $0, userKey: userKey)
        }
        var topics = [Data : Topic]()
        try object.topics.forEach {
            let topic = try Topic(object: $0)
            topics[topic.id] = topic
        }
        self.topics = topics
        super.init(url: url, appId: object.appication)
    }
}

private extension Data {
    
    /// Encodes data to a base64-url encoded string.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    ///
    /// - parameter options: The options to use for the encoding. Default value is `[]`.
    /// - returns: The base64-url encoded string.
    var url: String {
        return base64EncodedString().base64URLEscaped()
    }
}

private extension String {
    
    /// Converts a base64 encoded string to a base64-url encoded string.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    func base64URLEscaped() -> String {
        return replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
