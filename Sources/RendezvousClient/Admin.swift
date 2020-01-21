//
//  File.swift
//  
//
//  Created by Christoph on 09.01.20.
//

import Foundation
import Alamofire

public final class Admin: Server {
    
    /// The default admin token when setting up a new server.
    public static var defaultAdminToken: Data {
        Data(repeating: 0, count: Server.authTokenLength)
    }
    
    /// The administrator token
    private(set) public var adminToken: Data
    
    /**
     Create an admin connection to a server.
     
     - Parameter url: The url to the server.
     - Parameter token: The access token (defaults to an empty token)
     - Note: When a server is initally created, the default token is set.
     - Warning: New servers should be updated immediately with the `updateAdminToken(completion:)` function.
     */
    public init(server url: URL, token: Data = Admin.defaultAdminToken) {
        self.adminToken = token
        super.init(url: url)
    }
    
    // MARK: Headers
    
    /// The HTTP headers with the admin authentication token.
    private var authTokenHeaders: HTTPHeaders {
        var headers = HTTPHeaders()
        headers.add(authToken: adminToken)
        return headers
    }

    // MARK: Public functions

    /**
     Create a new admin token.
     
     This function can be used to create a new admin token when a server is initially configured.
     
     - Parameter onError: A closure called if the request fails.
     - Parameter onSuccess: A closure called if the request succeeds.
     */
    public func updateAdminToken(onError: @escaping RendezvousErrorHandler, onSuccess: @escaping () -> Void) {
        download("admin/renew", headers: authTokenHeaders, onError: onError) { data in
            guard data.count == Server.authTokenLength else {
                throw RendezvousError.invalidServerData
            }
            self.adminToken = data
            onSuccess()
        }
    }
    
    /**
     Reset a server which is configured for development.
     
     - Parameter onError: A closure called if the request fails.
     - Parameter onSuccess: A closure called if the request succeeds.
     */
    public func resetDevelopmentServer(onError: @escaping RendezvousErrorHandler, onSuccess: @escaping () -> Void) {
        download("admin/reset", headers: authTokenHeaders, onError: onError) {
            self.adminToken = Admin.defaultAdminToken
            onSuccess()
        }
    }
    
    /**
     Allow a new user to register with a server.
     
     - Parameter user: The name of the user to allow.
     - Parameter onError: A closure called with an error if the request was unsuccessful.
     - Parameter onSuccess: A closure called with the pin and pin expiry date for the user.
     - Parameter pin: The registration pin of the user
     - Parameter expiryDate: The date until the user is allowed to register.
     */
    public func allow(user: String, onError: @escaping RendezvousErrorHandler, onSuccess: @escaping (_ pin: Int, _ expiryDate: Date) -> Void) {
        var headers = authTokenHeaders
        headers.add(user: user)
        
        upload(to: "user/allow", headers: headers, onError: onError) { data in
            guard let object = try? RV_AllowedUser(serializedData: data) else {
                throw RendezvousError.invalidServerData
            }
            let pin = Int(object.pin)
            let expiry = Date(timeIntervalSince1970: TimeInterval(object.expiry))
            onSuccess(pin, expiry)
        }
    }
    
}
