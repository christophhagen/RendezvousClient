import XCTest
@testable import RendezvousClient

let url = URL(string: "http://localhost:8080")!

final class AdminTests: XCTestCase {
    
    static var allTests = [
        ("testAdminTokenUpdate", testAdminTokenUpdate),
    ]
    
    let server = Admin(newServer: url)
    
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
        
        server.resetDevelopmentServer { success in
            XCTAssertTrue(success)
            e.fulfill()
        }
        
        self.wait(for: [e], timeout: 10)
    }
    
    func testAdminTokenUpdate() {
        let e = self.expectation(description: "testUpdate")
        
        server.updateAdminToken { success in
            XCTAssertTrue(success)
            e.fulfill()
        }
        
        self.wait(for: [e], timeout: 10)
        
        // Check that new token can change again, and thus is valid
        let e2 = self.expectation(description: "testUpdate2")
        
        server.updateAdminToken() { success in
            XCTAssertTrue(success)
            e2.fulfill()
        }
        
        self.wait(for: [e2], timeout: 10)
    }
    
    private func allowUser(_ user: String) -> Int? {
        let e = self.expectation(description: "testAllow")
        
        var pin: Int? = nil
        server.allow(user: user) { (data) in
            guard let info = data else {
                XCTFail("Failed to allow user")
                e.fulfill()
                return
            }
            // Check that expiry is at least 6 days in the future
            let time = Date().addingTimeInterval(60 * 60 * 32 * 6)
            XCTAssert(info.expiryDate > time)
            pin = info.pin
            e.fulfill()
        }
        self.wait(for: [e], timeout: 10)
        return pin
    }
    
    func testAllowUser() {
        _ = allowUser(user)
    }
    
    private func registerUser() -> User? {
        guard let pin = allowUser(user) else {
            return nil
        }
        let server = self.server.server
        
        let e = self.expectation(description: "testRegisterUser")
        var user: User? = nil
        do {
            try server.register(user: self.user, using: pin) { result in
                switch result {
                case .success(let newUser):
                    user = newUser
                case .failure(let error):
                    XCTFail("\(error)")
                }
                e.fulfill()
            }
            self.wait(for: [e], timeout: 10)
            return user
        } catch {
            XCTFail("\(error)")
            e.fulfill()
            return nil
        }
    }
    
    func testRegisterUser() {
        _ = registerUser()
    }
    
    private func registerDevice() -> Device? {
        guard let user = registerUser() else {
            return nil
        }
        
        let e = self.expectation(description: #function)
        do {
            var device: Device? = nil
            try user.createDevice { result in
                switch result {
                case .success(let newDevice):
                    device = newDevice
                case .failure(let error):
                    XCTFail("\(error)")
                }
                e.fulfill()
            }
            self.wait(for: [e], timeout: 10)
            return device
        } catch {
            XCTFail("\(error)")
            e.fulfill()
            return nil
        }
    }
    
    func testRegisterDevice() {
        _ = registerDevice()
    }
    
    private func uploadPrekeys() -> Device? {
        guard let device = registerDevice() else {
            return nil
        }
        let e = self.expectation(description: #function)
        do {
            try device.uploadPreKeys(count: 50) { result in
                switch result {
                case .failure(let error):
                    XCTFail("\(error)")
                case .success(let count):
                    XCTAssertEqual(count, 50)
                }
                e.fulfill()
            }
            self.wait(for: [e], timeout: 10)
            return device
        } catch {
            XCTFail("\(error)")
            e.fulfill()
            return nil
        }
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
        device.uploadTopicKeys(count: 10) { result in
            switch result {
            case .failure(let error):
                XCTFail("\(error)")
            case .success(let count):
                XCTAssertEqual(count, 10)
                dev = device
            }
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
        device.getTopicKey(for: device.userKey) { result in
            switch result {
            case .failure(let error):
                XCTFail("\(error)")
            case .success(_):
                dev = device
            }
            e.fulfill()
        }
        self.wait(for: [e], timeout: 10)
        return dev
    }
    
    func testGetTopicKey() {
        _ = getTopicKey()
    }
    
    private func registerFull(user: String) -> Device? {
        guard let pin = allowUser(user) else {
            return nil
        }
        let server = self.server.server
        
        let e = self.expectation(description: #function)
        do {
            var device: Device? = nil
            try server.registerWithKeys(user: user, using: pin) { result in
                switch result {
                case .success(let newDevice):
                    device = newDevice
                case .failure(let error):
                    XCTFail("\(error)")
                }
                e.fulfill()
            }
            self.wait(for: [e], timeout: 10)
            return device
        } catch {
            XCTFail("\(error)")
            e.fulfill()
            return nil
        }
    }
    
    func testRegisterFull() {
        _ = registerFull(user: user)
    }
    
    func createTopic() -> (alice: Device, bob: Device, topic: Topic)? {
        guard let alice = registerFull(user: user), let bob = registerFull(user: "Bob") else {
            return nil
        }
        
        let e = self.expectation(description: #function)
        var topic: Topic? = nil
        alice.createTopic(with: [bob.userKey : .admin]) { result in
            switch result {
            case .success(let newTopic):
                topic = newTopic
            case .failure(let error):
                XCTFail("\(error)")
            }
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
        do {
            try data.alice.upload(message: message, metadata: metadata, to: data.topic) { result in
                switch result {
                case .success(let chain):
                    XCTAssertEqual(chain.index, 1)
                case .failure(let error):
                    XCTFail("\(error)")
                }
                e.fulfill()
            }
        } catch {
            XCTFail("\(error)")
            e.fulfill()
            return nil
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
        let expectation = self.expectation(description: #function + "2")
        data.bob.getMessages { err in
            guard let error = err else {
                expectation.fulfill()
                return
            }
            XCTFail("\(error)")
            expectation.fulfill()
            print("Finished")
        }
        self.wait(for: [delegate.expectation!, expectation], timeout: 10)
        guard let message = delegate.message else {
            XCTFail("No message")
            return
        }
        XCTAssertEqual(message.metadata, self.metadata)
        XCTAssertEqual(message.index, 0)
        XCTAssertTrue(delegate.verified)
    }
}
