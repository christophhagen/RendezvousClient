//
//  Server.swift
//  CEd25519
//
//  Created by Christoph on 10.01.20.
//

import Foundation
import Alamofire

public class Server {
    
    public let appId: String

    /// The server url
    public let url: URL
    
    /**
     Create a server connection without verifying that the server is available.
     - Note: Use the class function `connect(to:appId:completion)` to validate the server before creating an instance.
     - Parameter url: The url of the server (needs to be valid)
     - Parameter appId: The app identifier to use with the server.
     */
    public init(url: URL, appId: String) {
        self.url = url
        self.appId = appId
    }
    
    /**
     Connect to a server.
     - Parameter url: The server url
     - Parameter appId: The identifier for the application (`Server.appIdLength` bytes)
     - Parameter completion: A closure called when the request is completed.
     - Parameter server: The server instance, if the request is successful.
     */
    public static func connect(to url: URL, appId: String, completion: @escaping (_ server: Server?) -> Void) {
        guard appId.count <= Constants.maximumAppIdLength else {
            completion(nil)
            return
        }
        let pingURL = url.appendingPathComponent("ping")
        #warning("Pin server certificate.")
        AF.request(pingURL).response { response in
            guard response.error == nil else {
                completion(nil)
                return
            }
            let server = Server(url: url, appId: appId)
            completion(server)
        }
    }
    
    /**
     Register a user, and upload prekeys and topic keys.
     
     - Parameter userName: The name of the user.
     - Parameter pin: The pin given by the server administrator.
     - Parameter userIdentityKey: The optional private key of the user (a new key will be generated if this parameter is nil)
     - Parameter deviceIdentityKey: The optional private key of the device (a new key will be generated if this parameter is nil)
     - Parameter preKeyCount: The number of pre keys to initially create.
     - Parameter topicKeyCount: The number of topic keys to initially create.
     - Parameter completion: A closure called when the request is finished.
     - Parameter result: The created device connection, or an error.
     */
    public func register(
        user userName: String,
        using pin: Int,
        userIdentityKey: SigningPrivateKey? = nil,
        deviceIdentityKey: SigningPrivateKey? = nil,
        preKeys preKeyCount: Int = 50,
        topicKeys topicKeyCount: Int = 50,
        onError: @escaping (_ error: RendezvousError) -> Void,
        onSuccess: @escaping (_ device: Device) -> Void) {
        
        catching(onError: onError) {
            // Create a new identity key pair
            let userKey = userIdentityKey ?? Crypto.newSigningKey()
            let deviceKey = deviceIdentityKey ?? Crypto.newSigningKey()
            
            // Create prekeys
            let (preKeys, preKeysPairs) = try Crypto.createPreKeys(count: preKeyCount, for: deviceKey)
            
            // Create topic keys
            let topicKeys = try Crypto.createTopicKeys(count: topicKeyCount, for: userKey)
            
            let user = try create(user: userName, userKey: userKey, deviceKey: deviceKey)
            
            let object = RV_RegistrationBundle.with {
                $0.info = user
                $0.pin = UInt32(pin)
                $0.preKeys = preKeys
                $0.topicKeys = topicKeys.map { $0.publicKeys.object }
            }
            
            let data = try object.serializedData()
            
            upload(data, to: "user/register", onError: onError) { data in
                guard data.count == Constants.authTokenLength else {
                    throw RendezvousError.invalidServerData
                }
                let connection = Device(
                    url: self.url,
                    appId: self.appId,
                    userKey: userKey,
                    info: user,
                    deviceKey: deviceKey,
                    authToken: data)
                connection.preKeys = preKeysPairs
                connection.topicKeys = topicKeys
                onSuccess(connection)
            }
        }
    }
    
    private func create(user: String, userKey: SigningPrivateKey, deviceKey: SigningPrivateKey) throws -> RV_InternalUser {
        let now = Date.secondsNow
        let device = RV_InternalUser.Device.with {
            $0.deviceKey = deviceKey.publicKey.rawRepresentation
            $0.creationTime = now
            $0.isActive = true
            $0.application = appId
        }
        
        var user = RV_InternalUser.with { info in
            info.publicKey = userKey.publicKey.rawRepresentation
            info.creationTime = now
            info.name = user
            info.devices = [device]
            info.timestamp = now
        }
        try user.sign(with: userKey)
        return user
    }
    
    func upload(_ data: Data = Data(), to path: String, headers: HTTPHeaders? = nil, onError: @escaping RendezvousErrorHandler, onSuccess: @escaping (_ data: Data) throws -> Void) {
        AF.upload(data, to: url.appendingPathComponent(path), headers: headers).responseData { resp in
            guard let response = resp.response else {
                onError(.noResponse)
                return
            }
            guard response.statusCode == 200 else {
                let error = RendezvousError(status: response.statusCode)
                onError(error)
                return
            }
            guard let data = resp.data else {
                onError(.noDataInResponse)
                return
            }
            do {
                try onSuccess(data)
            } catch let error as RendezvousError {
                onError(error)
            } catch {
                onError(.unknownError)
            }
        }
    }
    
    func upload(_ data: Data = Data(), to path: String, headers: HTTPHeaders? = nil, onError: @escaping RendezvousErrorHandler, onSuccess: @escaping () throws -> Void) {
        AF.upload(data, to: url.appendingPathComponent(path), headers: headers).responseData { resp in
            guard let response = resp.response else {
                onError(.noResponse)
                return
            }
            guard response.statusCode == 200 else {
                let error = RendezvousError(status: response.statusCode)
                onError(error)
                return
            }
            do {
                try onSuccess()
            } catch let error as RendezvousError {
                onError(error)
            } catch {
                onError(.unknownError)
            }
        }
    }
    
    func download(_ path: String, headers: HTTPHeaders? = nil, onError: @escaping RendezvousErrorHandler, onSuccess: @escaping (_ data: Data) throws -> Void) {
        AF.request(url.appendingPathComponent(path), headers: headers).responseData { resp in
            guard let response = resp.response else {
                onError(.noResponse)
                return
            }
            guard response.statusCode == 200 else {
                let error = RendezvousError(status: response.statusCode)
                onError(error)
                return
            }
            guard let data = resp.data else {
                onError(.noDataInResponse)
                return
            }
            do {
                try onSuccess(data)
            } catch let error as RendezvousError {
                onError(error)
            } catch {
                onError(.unknownError)
            }
        }
    }
    
    func download(_ path: String, headers: HTTPHeaders? = nil, onError: @escaping RendezvousErrorHandler, onSuccess: @escaping () throws -> Void) {
        AF.request(url.appendingPathComponent(path), headers: headers).responseData { resp in
            guard let response = resp.response else {
                onError(.noResponse)
                return
            }
            guard response.statusCode == 200 else {
                let error = RendezvousError(status: response.statusCode)
                onError(error)
                return
            }
            do {
                try onSuccess()
            } catch let error as RendezvousError {
                onError(error)
            } catch {
                onError(.unknownError)
            }
        }
    }
    
    
}
