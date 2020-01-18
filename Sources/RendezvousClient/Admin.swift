//
//  File.swift
//  
//
//  Created by Christoph on 09.01.20.
//

import Foundation

public final class Admin {
    
    static var sessionConfiguration: URLSessionConfiguration {
        let config = URLSessionConfiguration()
        config.tlsMinimumSupportedProtocol = .tlsProtocol12
        return config
    }
    
    static var defaultAdminToken: Data {
        Data(repeating: 0, count: Server.authTokenLength)
    }
    
    public let serverURL: URL
    
    private let urlSession: URLSession
    
    var adminToken: Data
    
    var server: Server {
        Server(url: serverURL)
    }
    
    public init(newServer url: URL) {
        self.serverURL = url
        self.adminToken = Admin.defaultAdminToken
        self.urlSession = URLSession()
        //self.urlSession = URLSession(configuration: RendezvousServerAdmin.sessionConfiguration)
    }
    
    // MARK: Requests
    
    private func request(to path: String) -> URLRequest {
        let url = serverURL.appendingPathComponent(path)
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.add(authToken: adminToken)
        return request
    }
    
    private var adminRenewRequest: URLRequest {
        return request(to: "admin/renew")
    }
    
    private var serverResetRequest: URLRequest {
        return request(to: "admin/reset")
    }
    
    func addUserRequest(_ user: String) -> URLRequest {
        var request = self.request(to: "user/allow")
        request.httpMethod = "POST"
        request.add(user: user)
        return request
    }
    
    private func make(_ request: URLRequest, completion: @escaping (_ success: Bool, _ data: Data?) -> Void) {
        let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
            guard let r = response as? HTTPURLResponse, r.statusCode == 200 else {
                completion(false, nil)
                return
            }
            guard error == nil else {
                print(error!)
                completion(false, nil)
                return
            }
            completion(true, data)
        }
        task.resume()
    }
    
    // MARK: Public functions

    public func updateAdminToken(completion: @escaping (Bool) -> Void) {
        make(adminRenewRequest) { success, data in
            guard success,
                let d = data,
                d.count == Server.authTokenLength else {
                    completion(false)
                    return
            }
            self.adminToken = d
            completion(true)
        }
    }
    
    public func resetDevelopmentServer(completion: @escaping (Bool) -> Void) {
        make(serverResetRequest) { success, _ in
            guard success else {
                completion(false)
                return
            }
            self.adminToken = Admin.defaultAdminToken
            completion(true)
        }
    }
    
    public func allow(user: String, completion: @escaping ((pin: Int, expiryDate: Date)?) -> Void) {
        let request = addUserRequest(user)
        make(request) { (success, data) in
            guard success else {
                completion(nil)
                return
            }
            guard let d = data, let object = try? RV_AllowedUser(serializedData: d) else {
                completion(nil)
                return
            }
            let pin = Int(object.pin)
            let expiry = Date(timeIntervalSince1970: TimeInterval(object.expiry))
            completion((pin: pin, expiryDate: expiry))
        }
    }
    
}
