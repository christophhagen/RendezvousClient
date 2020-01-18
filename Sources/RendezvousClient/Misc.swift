//
//  Misc.swift
//  Alamofire
//
//  Created by Christoph on 15.01.20.
//

import Foundation

func catching<T>(completion: @escaping (Result<T, RendezvousError>) -> Void, block: @escaping () throws -> Void) {
    do {
        try block()
    } catch let error as RendezvousError {
        completion(.failure(error))
    } catch {
        completion(.failure(.unknownError))
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
