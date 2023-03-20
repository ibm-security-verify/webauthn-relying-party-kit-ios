//
// Copyright contributors to the IBM Security Verify Relying Party Kit for iOS project
//

import XCTest
@testable import RelyingPartyKit

final class RelyingPartyKitTests: XCTestCase {
    let baseURL = "https://rps-app.vb76iz9iykg.au-syd.codeengine.appdomain.cloud"
    
    func testAuthenticate() async throws {
        // Where
        let client = RelyingPartyClient(baseURL: URL(string: baseURL)!)
        
        // When
        do {
            _ = try await client.authenticate(username: "account@example.com", password: "a1b2c3d4")
        }
        catch let error {
            // Then
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
    
    func testSignup() async throws {
        // Where
        let client = RelyingPartyClient(baseURL: URL(string: baseURL)!)
        
        // When
        let result = try await client.signup(name: "Norm", email: "norm@mailinator.com")
        
        // Then
        XCTAssertNotNil(result)
        
    }
    
    func testValidate() async throws {
        // Given
        let client = RelyingPartyClient(baseURL: URL(string: baseURL)!)
        
        // When
        do {
            _ = try await client.validate(transactionId: "7705d361-f014-44c1-bae4-2877a0c962b6", otp: "123456")
        }
        catch let error {
            // Then
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
    
    func testChallengeAssertion() async throws {
        // Given
        let client = RelyingPartyClient(baseURL: URL(string: baseURL)!)
        
        // When
        let result = try await client.challenge(type: .assertion)
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testChallengeAttestation() async throws {
        // Given
        let client = RelyingPartyClient(baseURL: URL(string: baseURL)!)
        
        // When
        do {
            let token = try await client.authenticate(username: "account@example.com", password: "a1b2c3d4")
            _ = try await client.challenge(type: .attestation, token: token)
        }
        catch let error {
            // Then
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
    
    func testRegister() async throws {
        // Given
        let client = RelyingPartyClient(baseURL: URL(string: baseURL)!)
        
        // When
        do {
            let token = try await client.authenticate(username: "account@example.com", password: "a1b2c3d4")
            _ = try await client.register(nickname: "John's iPhone",
                                          clientDataJSON: Data("clientDataJSON".utf8),
                                          attestationObject: Data("attestationObject".utf8),
                                          credentialId: Data("credentialId".utf8),
                                          token: token)
        }
        catch let error {
            // Then
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
    
    func testSignin() async throws {
        // Given
        let client = RelyingPartyClient(baseURL: URL(string: baseURL)!)
        
        // When
        do {
            _ = try await client.signin(signature: Data("signature".utf8),
                                        clientDataJSON: Data("clientDataJSON".utf8),
                                        authenticatorData: Data("authenticatorData".utf8),
                                        credentialId: Data("credentialId".utf8),
                                        userId: Data("userId".utf8))
        }
        catch let error {
            // Then
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
}
