import XCTest
@testable import RendezvousClient

let url = URL(string: "http://localhost:8080")!

final class AdminTests: XCTestCase {
    
    static var allTests = [
        ("testAdminTokenUpdate", testAdminTokenUpdate),
    ]
    
    let server = Admin(server: url, appId: "Rendezvous".data(using: .utf8)!)
    
    let user = "Alice"
    
    let message = Data(repeating: 42, count: 250)
    
    let metadata = Data(repeating: 42, count: 42)

    override func setUp() {
        resetServer()
    }
    
    override func tearDown() {
        resetServer()
    }
    
    func testPing() {
        
    }
    
    func testReset() {
        
    }
    
    func resetServer() {
        let e = self.expectation(description: "testReset")
        
        server.resetDevelopmentServer(onError: { error in
            XCTFail("\(error)")
            e.fulfill()
        }) {
            e.fulfill()
        }
        
        self.wait(for: [e], timeout: 10)
    }
    
    func testAdminTokenUpdate() {
        let e = self.expectation(description: "testUpdate")
        
        server.updateAdminToken(onError: { error in
            XCTFail("\(error)")
            e.fulfill()
        }) {
            e.fulfill()
        }
        
        self.wait(for: [e], timeout: 10)
        
        // Check that new token can change again, and thus is valid
        let e2 = self.expectation(description: "testUpdate2")
        
        server.updateAdminToken(onError: { error in
            XCTFail("\(error)")
            e2.fulfill()
        }) {
            e2.fulfill()
        }
        
        self.wait(for: [e2], timeout: 10)
    }
    
    private func allowUser(_ user: String) -> Int? {
        let e = self.expectation(description: "testAllow")
        
        var pin: Int? = nil
        server.allow(user: user, onError: { error in
            XCTFail("\(error)")
            e.fulfill()
        }) { receivedPin, expiryDate in
            // Check that expiry is at least 6 days in the future
            let time = Date().addingTimeInterval(60 * 60 * 32 * 6)
            XCTAssert(expiryDate > time)
            pin = receivedPin
            e.fulfill()
        }
        
        self.wait(for: [e], timeout: 10)
        return pin
    }
    
    func testAllowUser() {
        _ = allowUser(user)
    }
    
    private func registerUser(_ user: String) -> Device? {
        guard let pin = allowUser(user) else {
            return nil
        }
        
        let e = self.expectation(description: #function)
        
        var device: Device? = nil
        server.register(user: user, using: pin, onError: { error in
            XCTFail("\(error)")
            e.fulfill()
        }) { newDevice in
            device = newDevice
            e.fulfill()
        }
        self.wait(for: [e], timeout: 10)
        return device
    }
    
    func testRegisterDevice() {
        _ = registerUser(user)
    }
    
    private func uploadPrekeys() -> Device? {
        guard let device = registerUser(user) else {
            return nil
        }
        let e = self.expectation(description: #function)
        
        var dev: Device? = nil
        device.uploadPreKeys(count: 50, onError: { error in
            XCTFail("\(error)")
            e.fulfill()
        }) {
            dev = device
            e.fulfill()
        }
        self.wait(for: [e], timeout: 10)
        return dev
        
    }
    
    func testUploadPrekeys() {
        _ = uploadPrekeys()
    }
    
    private func uploadTopicKeys() -> Device? {
        guard let device = uploadPrekeys() else {
            return nil
        }
        
        let e = self.expectation(description: #function)

        var dev: Device? = nil
        device.uploadTopicKeys(count: 10, onError: { error in
            XCTFail("\(error)")
            e.fulfill()
        }) { count in
            XCTAssertEqual(count, 10)
            dev = device
            e.fulfill()
        }
        self.wait(for: [e], timeout: 10)
        return dev
    }
    
    func testUploadTopicKeys() {
        _ = uploadTopicKeys()
    }
    
    private func getTopicKey() -> Device? {
        guard let device = uploadTopicKeys() else {
            return nil
        }
        
        let e = self.expectation(description: #function)

        var dev: Device? = nil
        device.getTopicKey(for: device.userKey, onError: { error in
            XCTFail("\(error)")
            e.fulfill()
        }) { _ in
            dev = device
            e.fulfill()
        }
        self.wait(for: [e], timeout: 10)
        return dev
    }
    
    func testGetTopicKey() {
        _ = getTopicKey()
    }
    
    func createTopic() -> (alice: Device, bob: Device, topic: Topic)? {
        guard let alice = registerUser(user), let bob = registerUser("Bob") else {
            return nil
        }
        
        let e = self.expectation(description: #function)
        var topic: Topic? = nil
        alice.createTopic(with: [(bob.userKey, Topic.Member.Role.admin)], onError: { error in
            XCTFail("\(error)")
            e.fulfill()
        }) { newTopic in
            topic = newTopic
            e.fulfill()
        }
        self.wait(for: [e], timeout: 10)
        if let t = topic {
            return (alice, bob, t)
        }
        return nil
    }
    
    func testCreateTopic() {
        _ = createTopic()
    }
    
    func uploadMessage() -> (alice: Device, bob: Device, topic: Topic)? {
        guard let data = createTopic() else {
            return nil
        }
        let e = self.expectation(description: #function)
        data.alice.upload(message: message, metadata: metadata, to: data.topic, onError: { error in
            XCTFail("\(error)")
            e.fulfill()
        }) { chain in
            XCTAssertEqual(chain.index, 1)
            e.fulfill()
        }
        self.wait(for: [e], timeout: 10)
        return data
    }
    
    func testUploadMessage() {
        _ = uploadMessage()
    }
    func testReceiveMessage() {
        guard let data = uploadMessage() else {
            return
        }
        let delegate = TestDelegate()
        data.bob.delegate = delegate
        // Expect topic update and message
        delegate.set(expectation: self.expectation(description: #function), after: 2)
        let e = self.expectation(description: #function + "2")
        data.bob.getMessages(onError: { error in
            XCTFail("\(error)")
            e.fulfill()
        }) {
            e.fulfill()
        }
        self.wait(for: [delegate.expectation!, e], timeout: 10)
        guard let message = delegate.message else {
            XCTFail("No message")
            return
        }
        XCTAssertEqual(message.metadata, self.metadata)
        XCTAssertEqual(message.nextChainIndex, 1)
        XCTAssertTrue(delegate.verified)
    }
}
