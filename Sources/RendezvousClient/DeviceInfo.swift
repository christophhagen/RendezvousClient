//
//  DeviceInfo.swift
//  Alamofire
//
//  Created by Christoph on 10.01.20.
//

import Foundation
import CryptoKit25519

public struct DeviceInfo {
    
    public let publicKey: SigningPublicKey
    
    public let created: Date
    
    public let isActive: Bool

    init(object: RV_UserDevice) throws {
        self.publicKey = try .init(rawRepresentation: object.deviceKey)
        self.created = Date(seconds: object.creationTime)
        self.isActive = object.isActive
    }
    
    var object: RV_UserDevice {
        .with {
            $0.deviceKey = publicKey.rawRepresentation
            $0.creationTime = created.seconds
            $0.isActive = isActive
        }
    }
}
