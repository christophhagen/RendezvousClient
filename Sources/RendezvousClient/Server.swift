//
//  Server.swift
//  CEd25519
//
//  Created by Christoph on 10.01.20.
//

import Foundation
import Alamofire
import CryptoKit25519


public class Server {
    
    static let authTokenLength = 16
    
    /// The server url
    let url: URL
    
    
    init(url: URL) {
        self.url = url
    }
    
    /**
     Connect to a server.
     - Parameter url: The server url
     - Parameter completion: A closure called when the request is completed.
     - Parameter server: The server instance, if the request is successful.
     */
    public static func connect(to url: URL, completion: @escaping (_ server: Server?) -> Void) {
        let pingURL = url.appendingPathComponent("ping")
        #warning("Pin server certificate.")
        AF.request(pingURL).response { response in
            guard response.error == nil else {
                completion(nil)
                return
            }
            let server = Server(url: url)
            completion(server)
        }
    }
    
    /**
     Register a user with the server.
     
     - Parameter user: The name of the user.
     - Parameter pin: The pin given by the server administrator.
     - Parameter completion: A closure called when the request is finished.
     - Parameter result: The created user connection, or an error.
     */
    public func register(user: String, using pin: Int, completion: @escaping (_ result: Result<User, RendezvousError>) -> Void) throws {
        // Create a new identity key pair
        Crypto.ensureRandomness()
        let userKey = try SigningPrivateKey()
        
        let headers: HTTPHeaders = [
            "pin": "\(pin)"
        ]
        
        let seconds = Date().seconds
        let info = RV_InternalUser.with {
            $0.publicKey = userKey.publicKey.rawRepresentation
            $0.name = user
            $0.devices = []
            $0.creationTime = seconds
            $0.timestamp = seconds
        }
        
        let data = try info.data(signedWith: userKey)
        
        upload(data, to: "user/register", headers: headers, onSuccess: {
            User(url: self.url, userKey: userKey, info: info)
        }, completion: completion)
    }
    
    /**
     Register a user, and upload prekeys and topic keys.
     
     - Parameter user: The name of the user.
     - Parameter pin: The pin given by the server administrator.
     - Parameter completion: A closure called when the request is finished.
     - Parameter result: The created device connection, or an error.
     */
    public func registerWithKeys(user: String, using pin: Int, completion: @escaping (_ result: Result<Device, RendezvousError>) -> Void) throws {
        
        // Create a new identity key pair
        Crypto.ensureRandomness()
        let userKey = try SigningPrivateKey()
        let deviceKey = try SigningPrivateKey()
        
        let (preKeys, preKeysPairs) = try Device.createPreKeys(count: 50, for: deviceKey)
        
        var topicKeys = [SigningPublicKey : Topic.Keys]()
        try (0..<50).forEach { _ in
            let key = try Topic.Keys(userKey: userKey)
            topicKeys[key.publicKeys.signatureKey] = key
        }
        
        let user = try create(user: user, userKey: userKey, deviceKey: deviceKey)
        
        let object = RV_RegistrationBundle.with {
            $0.info = user
            $0.pin = UInt32(pin)
            $0.preKeys = preKeys
            $0.topicKeys = topicKeys.values.map { $0.publicKeys.object }
        }
        
        let data = try object.serializedData()
        
        upload(data, to: "user/full", transform: { data -> Device in
            guard data.count == Server.authTokenLength else {
                throw RendezvousError.invalidServerData
            }
            let connection = Device(
                url: self.url,
                userKey: userKey,
                info: user,
                deviceKey: deviceKey,
                authToken: data)
            connection.preKeys = preKeysPairs
            connection.topicKeys = topicKeys
            return connection
        }, completion: completion)
    }
    
    private func create(user: String, userKey: SigningPrivateKey, deviceKey: SigningPrivateKey) throws -> RV_InternalUser {
        let now = Date.secondsNow
        let device = RV_UserDevice.with {
            $0.deviceKey = deviceKey.publicKey.rawRepresentation
            $0.creationTime = now
            $0.isActive = true
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
    
    /**
     Upload data and transform the resulting data.
     */
    func upload<T>(_ data: Data, to path: String, headers: HTTPHeaders? = nil, transform: @escaping (Data) throws -> T, completion: @escaping (Result<T, RendezvousError>) -> Void) {
        AF.upload(data, to: url.appendingPathComponent(path), headers: headers).responseData { resp in
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
                completion(.failure(.noDataInReponse))
                return
            }
            do {
                let t = try transform(data)
                completion(.success(t))
            } catch let error as RendezvousError {
                completion(.failure(error))
            } catch {
                completion(.failure(.unknownError))
            }
        }
    }
    
    /**
     Upload data.
     */
    func upload<T>(_ data: Data, to path: String, headers: HTTPHeaders? = nil, onSuccess: @escaping () -> T, completion: @escaping (Result<T, RendezvousError>) -> Void) {
        AF.upload(data, to: url.appendingPathComponent(path), headers: headers).responseData { resp in
            guard let response = resp.response else {
                completion(.failure(.noResponse))
                return
            }
            guard response.statusCode == 200 else {
                let error = RendezvousError(status: response.statusCode)
                completion(.failure(error))
                return
            }
            let result = onSuccess()
            completion(.success(result))
        }
    }
    
    func download<T>(_ path: String, headers: HTTPHeaders? = nil, transform: @escaping (Data) throws -> T, completion: @escaping (Result<T, RendezvousError>) -> Void) {
        AF.request(url.appendingPathComponent(path), headers: headers).responseData { resp in
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
                completion(.failure(.noDataInReponse))
                return
            }
            do {
                let t = try transform(data)
                completion(.success(t))
            } catch let error as RendezvousError {
                completion(.failure(error))
            } catch {
                completion(.failure(.unknownError))
            }
        }
    }
    
    func download(_ path: String, headers: HTTPHeaders? = nil, process: @escaping (Data) throws -> Void, completion: @escaping (RendezvousError?) -> Void) {
        AF.request(url.appendingPathComponent(path), headers: headers).responseData { resp in
            guard let response = resp.response else {
                completion(.noResponse)
                return
            }
            guard response.statusCode == 200 else {
                let error = RendezvousError(status: response.statusCode)
                completion(error)
                return
            }
            guard let data = resp.data else {
                completion(.noDataInReponse)
                return
            }
            do {
                try process(data)
                completion(nil)
            } catch let error as RendezvousError {
                completion(error)
            } catch {
                completion(.unknownError)
            }
        }
    }
    
}
