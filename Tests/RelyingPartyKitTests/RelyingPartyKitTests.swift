//
// Copyright contributors to the IBM Security Verify Relying Party Kit for iOS project
//

import XCTest
@testable import RelyingPartyKit

final class RelyingPartyKitTests: XCTestCase {
    /// Replace this placeholder with a value representing your environment.
    let baseURL = "example.com"
    
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
        let result: CredentialAssertionOptions = try await client.challenge()
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testChallengeAssertionWithDisplayName() async throws {
        // Given
        let client = RelyingPartyClient(baseURL: URL(string: baseURL)!)
        
        // When
        let result: CredentialAssertionOptions = try await client.challenge(displayName: "John")
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testChallengeAssertionWithToken() async throws {
        // Given
        let client = RelyingPartyClient(baseURL: URL(string: baseURL)!)
        
        // When
        let token = try await client.authenticate(username: "account@example.com", password: "a1b2c3d4")
        let result: CredentialAssertionOptions = try await client.challenge(token: token)
        
        // Then
        XCTAssertNotNil(result)
    }
    
    func testChallengeAssertionWithTokenAndDisplayName() async throws {
        // Given
        let client = RelyingPartyClient(baseURL: URL(string: baseURL)!)
        
        // When
        let token = try await client.authenticate(username: "account@example.com", password: "a1b2c3d4")
        let result: CredentialAssertionOptions = try await client.challenge(displayName: "John", token: token)
        
        // Then
        XCTAssertNotNil(result)
    }
    
   func testChallengeAttestationErrorNoDisplay() async throws {
        // Given
        let client = RelyingPartyClient(baseURL: URL(string: baseURL)!)
        
        // When
        do {
            let token = try await client.authenticate(username: "account@example.com", password: "a1b2c3d4")
            let _: CredentialRegistrationOptions = try await client.challenge(token: token)
            
            // Then
        }
        catch let error {
            // Then
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
    
    func testChallengeAttestationWithDisplayName() async throws {
        // Given
        let client = RelyingPartyClient(baseURL: URL(string: baseURL)!)
        
        // When
        do {
            let token = try await client.authenticate(username: "account@example.com", password: "a1b2c3d4")
            let result: CredentialRegistrationOptions = try await client.challenge(displayName: "John", token: token, headers: ["foo": "bar", "pet": "dog"])
            
            // Then
            XCTAssertNotNil(result)
            
            // Then
            XCTAssertNotNil(result.user.displayName == "John")
        }
        catch let error {
            // Then
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
    
    func testChallengeAttestationWithHeaders() async throws {
        // Given
        let client = RelyingPartyClient(baseURL: URL(string: baseURL)!)
        
        // When
        do {
            let token = try await client.authenticate(username: "account@example.com", password: "a1b2c3d4")
            let result: CredentialRegistrationOptions = try await client.challenge(displayName: "John", token: token, headers: ["foo": "bar", "pet": "dog"])
            
            // Then
            XCTAssertNotNil(result)
            
            // Then
            XCTAssertNotNil(result.user.displayName == "John")
        }
        catch let error {
            // Then
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
    
    func testRegisterWithToken() async throws {
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
    
    func testRegisterWithHeaders() async throws {
        // Given
        let client = RelyingPartyClient(baseURL: URL(string: baseURL)!)
        
        // When
        do {
            _ = try await client.register(nickname: "John's iPhone",
                                          clientDataJSON: Data("clientDataJSON".utf8),
                                          attestationObject: Data("attestationObject".utf8),
                                          credentialId: Data("credentialId".utf8),
                                          headers: ["auth_session": "a1b2v3d4"])
        }
        catch let error {
            // Then
            XCTAssertNotNil(error, error.localizedDescription)
        }
    }
    
    func testSigninToken() async throws {
        // Given
        let client = RelyingPartyClient(baseURL: URL(string: baseURL)!)
        
        // When
        do {
            let _: Token = try await client.signin(signature: Data("signature".utf8),
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
    
    func testSigninCookie() async throws {
        // Given
        let client = RelyingPartyClient(baseURL: URL(string: baseURL)!)
        
        // When
        do {
            let _: Cookies = try await client.signin(signature: Data("signature".utf8),
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

