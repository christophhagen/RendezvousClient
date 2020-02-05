//
//  Chain.swift
//  Alamofire
//
//  Created by Christoph on 15.01.20.
//

import Foundation

public struct Chain {
    
    public let index: UInt32
    
    public let output: Data
    
    init(object: RV_TopicState.ChainState) {
        self.index = object.chainIndex
        self.output = object.output
    }
}
