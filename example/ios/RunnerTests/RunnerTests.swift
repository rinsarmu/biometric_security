import Flutter
import UIKit
import XCTest

@testable import biometric_security

/// Unit tests for the iOS security layer. Policy parsing and availability wiring
/// run on the simulator; Keychain/Secure-Enclave biometric flows require a real
/// device and are covered by manual/integration testing.
class RunnerTests: XCTestCase {

    func testPolicyConfigSecureDefault() {
        let p = PolicyConfig.secureDefault()
        XCTAssertEqual(p.minimumStrength, "strong")
        XCTAssertFalse(p.deviceCredentialFallback)
        XCTAssertTrue(p.invalidateOnEnrollment)
        XCTAssertFalse(p.afterFirstUnlock)
        XCTAssertTrue(p.requiresAuthentication)
    }

    func testPolicyConfigEncryptedOnly() {
        let p = PolicyConfig.from(["minimumStrength": "none"])
        XCTAssertFalse(p.requiresAuthentication)
    }

    func testPolicyConfigParsesWeakerOptions() {
        let p = PolicyConfig.from([
            "minimumStrength": "strong",
            "deviceCredentialFallback": "allow",
            "enrollmentBinding": "persistAcrossEnrollment",
            "accessibility": "afterFirstUnlockThisDeviceOnly",
            "hardwareRequirement": "requireSecureHardware",
        ])
        XCTAssertTrue(p.deviceCredentialFallback)
        XCTAssertFalse(p.invalidateOnEnrollment)
        XCTAssertTrue(p.afterFirstUnlock)
        XCTAssertTrue(p.requireSecureHardware)
    }

    func testProtectionClassMapping() {
        XCTAssertEqual(
            PolicyConfig.secureDefault().protectionClass,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
        XCTAssertEqual(
            PolicyConfig.from(["accessibility": "afterFirstUnlockThisDeviceOnly"])
                .protectionClass,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
    }

    func testGetAvailabilityReturnsHonestMap() {
        let plugin = BiometricSecurityPlugin()
        let call = FlutterMethodCall(methodName: "getAvailability", arguments: nil)

        let done = expectation(description: "result called")
        plugin.handle(call) { result in
            let map = result as? [String: Any?]
            XCTAssertNotNil(map)
            // Honesty invariant: a specific modality can never be forced (INV-4).
            let guarantees = map?["guarantees"] as? [String: Any?]
            XCTAssertEqual(guarantees?["canForceSpecificModality"] as? Bool, false)
            done.fulfill()
        }
        waitForExpectations(timeout: 2)
    }
}
