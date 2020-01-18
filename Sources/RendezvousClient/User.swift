//
//  UserConnection.swift
//  Alamofire
//
//  Created by Christoph on 10.01.20.
//

import Foundation
import CryptoKit25519
import Alamofire

public protocol UserDelegate: class {
    
    func user(changedDevice device: DeviceInfo)
    
    func user(addedDevice device: DeviceInfo)
    
    func user(removedDevice device: DeviceInfo)
}

public class User: Server {
    
    /// The public identity key of the user
    let userKey: SigningPublicKey
    
    /// The private identity key of the user
    let userPrivateKey: SigningPrivateKey
    
    /// Info about the user and the devices
    private var object: RV_InternalUser
    
    weak var userDelegate: UserDelegate?
    
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
    
    init(url: URL, userKey: SigningPrivateKey, info: RV_InternalUser) {
        self.userPrivateKey = userKey
        self.userKey = userKey.publicKey
        self.object = info
        super.init(url: url)
    }
    
    func update(info: RV_InternalUser) throws {
        guard info.timestamp > object.timestamp else {
            throw RendezvousError.requestOutdated
        }
        try info.isFreshAndSigned()
        
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
        guard let delegate = userDelegate else {
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
    
    /**
     Create a device for a user.
     
     - Parameter completion: A closure called when the request finishes.
     - Parameter result: The device, or an error.
     */
    public func createDevice(completion: @escaping (_ result: Result<Device, RendezvousError>) -> Void) throws {
        // Create the new device
        Crypto.ensureRandomness()
        let deviceKey = try SigningPrivateKey()
        
        // Create the device
        let seconds = Date().seconds
        let device = RV_UserDevice.with {
            $0.deviceKey = deviceKey.publicKey.rawRepresentation
            $0.creationTime = seconds
            $0.isActive = true
        }
        
        // Add the device, update the info, and sign the result.
        var newInfo = object
        newInfo.devices.append(device)
        newInfo.timestamp = seconds
        try newInfo.sign(with: userPrivateKey)
        
        // Serialize the data and start the request.
        let data = try newInfo.serializedData()
        upload(data, to: "device/register", transform: { data -> Device in
            guard data.count == Server.authTokenLength else {
                throw RendezvousError.invalidServerData
            }
            
            return Device(
                url: self.url,
                userKey: self.userPrivateKey,
                info: newInfo,
                deviceKey: deviceKey,
                authToken: data)
        }, completion: completion)
    }
    
    func makeTopicKeys(count: Int) throws -> [Topic.Keys] {
        try (0..<count).map { _ in
            try Topic.Keys(userKey: userPrivateKey)
        }
    }
    
    func makeTopicKeys(fromPreKeys preKeys: RV_DevicePreKeyBundle) throws -> (topicKeys: [Topic.Keys], messages: [RV_TopicKeyMessageList]) {
        var existingDevices = Set(object.devices.map { $0.deviceKey })
        let count = Int(preKeys.keyCount)
        
        // Create the topic keys
        Crypto.ensureRandomness()
        let topicKeys = try makeTopicKeys(count: count)
        
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
                    return try topicKeys[index].message(forDevice: device, withPrekey: key)
                }
            }
        }
        
        // Check that no prekeys for a device are missing
        guard existingDevices.isEmpty else {
            throw RendezvousError.invalidRequest
        }
        
        return (topicKeys, Array(messages.values))
    }
}
