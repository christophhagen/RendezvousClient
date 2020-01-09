import XCTest
@testable import RendezvousClient

final class RendezvousClientTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(RendezvousClient().text, "Hello, World!")
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}
