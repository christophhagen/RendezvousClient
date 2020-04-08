//
//  TopicMember.swift
//  Alamofire
//
//  Created by Christoph on 06.02.20.
//

import Foundation

extension Topic {
    
    /// A member of a topic
    public struct Member {
        
        /// The user identity key
        public let userKey: SigningPublicKey
        
        /// The signature key used when signing new messages
        public let signatureKey: SigningPublicKey
        
        /// The encryption key used to encrypt the message key
        public let encryptionKey: EncryptionPublicKey
        
        /// The permissions of the member
        private(set) public var role: Role
        
        /**
         Create a member from a protobuf object.
         
         - Parameter member: The protobuf object with the info
         */
        init(member: RV_Topic.MemberInfo) throws {
            self.userKey = try SigningPublicKey(rawRepresentation: member.info.userKey)
            self.signatureKey = try SigningPublicKey(rawRepresentation: member.signatureKey)
            self.encryptionKey = try EncryptionPublicKey(rawRepresentation: member.info.encryptionKey)
            self.role = try Role(object: member.role)
        }
        
        /// The member info converted to a Protobuf object
        var object: RV_Topic.MemberInfo {
            .with {
                $0.signatureKey = signatureKey.rawRepresentation
                $0.role = role.object
                $0.info = .with { info in
                    info.encryptionKey = encryptionKey.rawRepresentation
                    info.userKey = userKey.rawRepresentation
                }
            }
        }
        
        // MARK: Roles

        /// The role of a group member
        public enum Role {
            
            /// Admins are allowed to add and remove users, and read and write messages
            case admin
            
            /// Participants are allowed to read and write messages
            case participant
            
            /// Observers are allowed to read messages
            case observer
            
            var object: RV_Topic.MemberInfo.Role {
                switch self {
                case .admin: return .admin
                case .participant: return .participant
                case .observer: return .observer
                }
            }
            
            init(object: RV_Topic.MemberInfo.Role) throws {
                switch object {
                case .admin: self = .admin
                case .participant: self = .participant
                case .observer: self = .observer
                default:
                    throw RendezvousError.unknownError
                }
            }
        }
    }
}
