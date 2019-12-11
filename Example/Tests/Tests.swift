import XCTest
import Secp256k1Kit

class Tests: XCTestCase {

    func testExample() {
        let data = Data(repeating: 1, count: 32)
        let _ = Kit.createPublicKey(fromPrivateKeyData: data)
        XCTAssert(true, "Pass")
    }

}
