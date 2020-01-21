//
//  Misc.swift
//  Alamofire
//
//  Created by Christoph on 15.01.20.
//

import Foundation
import SwiftProtobuf

public typealias RendezvousErrorHandler = (_ error: RendezvousError) -> Void

func catching(onError: @escaping RendezvousErrorHandler, block: () throws -> Void) {
    do {
        try block()
    } catch let error as RendezvousError {
        onError(error)
    } catch _ as BinaryEncodingError {
        onError(.serializationFailed)
    } catch {
        onError(.unknownError)
    }
}

extension Array {
    
    func isSorted<T: Comparable>(by: (Element) -> T) -> Bool {
        guard count > 1 else {
            return true
        }
        for index in 1..<count {
            guard by(self[index-1]) < by(self[index]) else {
                return false
            }
        }
        return true
    }
}

extension Array where Element: Comparable {
    
    /// Indicate if the array is sorted in ascending order.
    var isSorted: Bool {
        guard count > 1 else {
            return true
        }
        for index in 1..<count {
            guard self[index-1] < self[index] else {
                return false
            }
        }
        return true
    }
}
