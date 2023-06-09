//
// Copyright contributors to the IBM Security Verify Relying Party Kit for iOS project
//

import Foundation

/// An RelyingPartyClient is a lightweight object to orchestrate WebAuthn requests that register and verify a fast identity on-line (FIDO) authenticator.
public struct RelyingPartyClient {
    let baseURL: URL
    let decoder: JSONDecoder
    
    /// Initializes the relying party client.
    /// - Parameters:
    ///   - baseURL: The relying party server hostname ``URL``.
    public init(baseURL: URL) {
        self.baseURL = baseURL
        self.decoder = JSONDecoder()
        self.decoder.dateDecodingStrategy = .iso8601
    }
    
    // MARK: User Authentication, Sign-up and Validation
    
    /// The user authentication request.
    /// - Parameters:
    ///   - username: The user's username.
    ///   - password: The users' password.
    /// - Returns: A ``Token`` representing an authenticated user.
    ///
    /// An example request for authenticating a user:
    /// ```
    /// // Create an instance of the client.
    /// let client = RelyingPartyClient(baseURL: URL(string: "https://example.com")!)
    /// let result = try await client.authenticate(username: "johnc@email.com", password: "a1b2c3d4")
    ///
    /// // Print the access token.
    /// print(result)
    /// ```
    public func authenticate(username: String, password: String) async throws -> Token {
        // Create and encode the username and password.
        let authenticate = UserAuthentication(username: username, password: password)
        let body = try JSONEncoder().encode(authenticate)
        let url = baseURL.appendingPathComponent("/v1/authenticate")
        
        // Set the request properties.
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        // Submit the request and decode the response.
        let (data, response) = try await URLSession.shared.upload(for: request, from: body)
        
        // Check the response status for 200 range.
        guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
            throw String(decoding: data, as: UTF8.self)
        }
        
        return try self.decoder.decode(Token.self, from: data)
    }
    
    /// Allows the user to sign up for an account.
    /// - Parameters:
    ///   - name: The formatted name of the user.
    ///   - email: The email address of the user.
    /// - Returns: A ``OTPChallenge`` structure that describes a one-time. password challenge.
    ///
    /// An example request for user sign-up:
    /// ```
    /// // Create an instance of the client.
    /// let client = RelyingPartyClient(baseURL: URL(string: "https://example.com")!)
    /// let result = try await client.signup(name: "John Citizen", email: "johnc@email.com")
    ///
    /// // Print the sign-up challenge.
    /// print(result)
    /// ```
    ///
    /// The replying party server will send the OTP challenge to the email provided.
    public func signup(name: String, email: String) async throws -> OTPChallenge {
        // Create and encode the name and email.
        let user = UserSignUp(name: name, email: email)
        let body = try JSONEncoder().encode(user)
        let url = baseURL.appendingPathComponent("/v1/signup")
        
        // Set the request properties.
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        // Submit the request and decode the response.
        let (data, response) = try await URLSession.shared.upload(for: request, from: body)
        
        // Check the response status for 200 range.
        guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
            throw String(decoding: data, as: UTF8.self)
        }
        
        return try self.decoder.decode(OTPChallenge.self, from: data)
    }
    
    /// Validate the user sign-up request.
    /// - Parameters:
    ///   - transactionId: The unique identifier of the verification
    ///   - otp: The one-time password value.
    ///
    /// An example request for validating an one-time password challenge:
    /// ```
    /// // Create an instance of the client.
    /// let client = RelyingPartyClient(baseURL: URL(string: "https://example.com")!)
    /// let result = try await client.validate(transactionId: "7705d361-f014-44c1-bae4-2877a0c962b6", otp: "123456")
    ///
    /// // Print the access token.
    /// print(result)
    /// ```
    ///
    /// A successful one-time password vallidation results in the user account being created.
    public func validate(transactionId: String, otp: String) async throws -> Token {
        // Create and encode the transaction identifier and otp.
        let validation = OTPVerification(transactionId: transactionId, otp: otp)
        let body = try JSONEncoder().encode(validation)
        let url = baseURL.appendingPathComponent("/v1/validate")
        
        // Set the request properties.
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        // Submit the request and decode the response.
        let (data, response) = try await URLSession.shared.upload(for: request, from: body)
        
        // Check the response status for 200 range.
        guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
            throw String(decoding: data, as: UTF8.self)
        }
        
        return try self.decoder.decode(Token.self, from: data)
    }
    
    
    // MARK: FIDO2 Device Registration and Verification (sign-in)
    
    /// A request to generate a WebAuthn challenge.
    /// - Parameters:
    ///   - displayName: The display name used by the authenticator for UI representation.
    ///   - token: Represents an access token.
    ///   - headers: A dictionary of custom headers to include in the request.
    ///
    ///
    /// The `headers` parameter is provided for convenience to support callers using cookie-based authentication.  The relying party server should also support cookie-based authentication for this method to complete.
    ///
    ///
    /// An example request for obtaining a challenge for registration:
    /// ```
    /// // Create an instance of the client.
    /// let client = RelyingPartyClient(baseURL: URL(string: "https://example.com")!)
    /// let token = try await client.authenticate(username: "johnc@email.com", password: "a1b2c3d4")
    /// let result: CredentialRegistrationOptions = try await client.challenge(displayName: "John Citizen iPhone", token: token)
    ///
    /// // Print the credential options.
    /// print(result)
    /// ```
    ///
    /// An example request for obtaining a challenge for verification:
    /// ```
    /// // Create an instance of the client.
    /// let client = RelyingPartyClient(baseURL: URL(string: "https://example.com")!)
    /// let result: CredentialAssertionOptions = try await client.challenge()
    ///
    /// // Print the challenge.
    /// print(result)
    /// ```
    ///
    /// A successful one-time password vallidation results in the user account being created.
    public func challenge<T>(displayName: String? = nil, token: Token? = nil, headers: [String: String]? = nil) async throws -> T where T: CredentialsOptions {
        // Create and encode the FIDO challenge request.
        let body = """
            {
                "type": "\(String(describing: T.self) == "CredentialAssertionOptions" ? "assertion" : "attestation")",
                "displayName": "\(displayName ?? "")"
            }
        """.data(using: .utf8)!
        let url = baseURL.appendingPathComponent("/v1/challenge")
        
        // Set the request properties.
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        // Add the authorization header if available.
        if let token = token {
            request.setValue(token.authorizationHeader, forHTTPHeaderField: "Authorization")
        }
        
        // Add additional headers if available.
        if let headers = headers, var allHeaders = request.allHTTPHeaderFields {
            allHeaders.merge(headers) { (current, _) in current }
            request.allHTTPHeaderFields = allHeaders
        }
        
        // Submit the request and decode the response.
        let (data, response) = try await URLSession.shared.upload(for: request, from: body)
        
        // Check the response status for 200 range.
        guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
            throw String(decoding: data, as: UTF8.self)
        }
        
        // Create the CredentialOptions object.
        return try self.decoder.decode(T.self, from: data)
    }
  
    /// A request to present the signed challenge to the server for verification.
    /// - Parameters:
    ///   - signature: The signature for the assertion.
    ///   - clientDataJSON: Raw data that contains a JSON-compatible encoding of the client data.
    ///   - authenticatorData: A byte sequence that contains additional information about the credential.
    ///   - credentialId: An identifier that the authenticator generates during registration to uniquely identify a specific credential.
    ///   - userId:The userId provided when creating this credential.
    /// - Returns: A ``Token`` representing an authenticated user.
    ///
    /// An example request perfroming a password-less sign-in using a registered FIDO authenticator:
    /// ```
    /// var token: Token?
    ///
    /// // Connect to a service with an existing account.
    /// let client = RelyingPartyClient(baseURL: URL(string: "https://example.com")!)
    ///
    /// // Obtain this from the server using client.challenge() based on return type.
    /// let result: CredentialAssertionOptions = try await client.challenge()
    ///
    /// let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider("example.com")
    /// let platformKeyRequest = platformProvider.createCredentialAssertionRequestWithChallenge(result.challenge)
    /// let authController = ASAuthorizationController([platformKeyRequest])
    /// authController.delegate = self
    /// authController.presentationContextProvider = self
    /// authController.performRequests()
    ///
    /// // Respond to the request.
    /// func authorizationController(controller: controller, didCompleteWithAuthorization: authorization) {
    ///  if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
    ///    // Take steps to verify the challenge.
    ///    token = try await client.signin(signature: credential.signature, clientDataJSON: credential.rawClientDataJSON, authenticatorData: credential.rawAuthenticatorData, credentialId: credential.credentialId, userId: credential.userID)
    ///  }
    /// }
    ///
    /// func authorizationController(controller: controller, didCompleteWithError: error) {
    ///  // Handle the error.
    ///}
    /// ```
    public func signin<T>(signature: Data, clientDataJSON: Data, authenticatorData: Data, credentialId: Data, userId: Data) async throws -> T where T: AuthenticationMethod {
        // Create and encode the FIDO2 registration data.
        let verification = FIDO2Verification(clientDataJSON: clientDataJSON.base64UrlEncodedString(),
                                             authenticatorData: authenticatorData.base64UrlEncodedString(),
                                             credentialId: credentialId.base64UrlEncodedString(),
                                             signature: signature.base64UrlEncodedString(),
                                             userHandle: userId.base64UrlEncodedString())
        let body = try JSONEncoder().encode(verification)
        let url = baseURL.appendingPathComponent("/v1/signin")
        
        // Set the request properties.
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        // Submit the request and decode the response.
        let (data, response) = try await URLSession.shared.upload(for: request, from: body)
        
        // Check the response status for 200 range.
        guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
            throw String(decoding: data, as: UTF8.self)
        }
        
        // Convert the response cookies into JSON
        if T.self is Cookies.Type, let headers = httpResponse.allHeaderFields as? [String: String] {
            let cookies = HTTPCookie.cookies(withResponseHeaderFields: headers, for: url)
            let values = cookies.reduce(into: [String: String]()) {
                $0[$1.name] = $1.value
            }
            
            // Convert the structure into Data object.
            let data = try JSONSerialization.data(withJSONObject: ["items": values])
            return try self.decoder.decode(T.self, from: data)
        }
                                                     
        return try self.decoder.decode(T.self, from: data)
    }
    
    /// A request to present an attestation object containing a public key to the server for attestation verification and storage.
    /// - Parameters:
    ///   - nickname: The friendly name for the registration.
    ///   - clientDataJSON: Raw data that contains a JSON-compatible encoding of the client data.
    ///   - attestationObject: A data object that contains the returned attestation.
    ///   - credentialId: An identifier that the authenticator generates during registration to uniquely identify a specific credential.
    ///   - headers: A dictionary of custom headers to include in the request.
    ///
    /// The `headers` parameter is provided for convenience to support callers using cookie-based authentication.  The relying party server should also support cookie-based authentication for this method to complete.  An example request for registering a FIDO authenticator:
    ///
    /// ```
    /// // Register a new account on a service
    /// let client = RelyingPartyClient(baseURL: URL(string: "https://example.com")!)
    ///
    /// // Obtain this from the server using client.challenge() based on return type.
    /// let result: CredentialRegistrationOptions = try await client.challenge(headers: ["auth_session": "e5f6g7h8"])
    ///
    /// let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider("example.com")
    /// let platformKeyRequest = platformProvider.createCredentialRegistrationRequest(challenge: result.challenge, name: result.user.name, userID: result.user.id)
    /// let authController = ASAuthorizationController([platformKeyRequest])
    /// authController.delegate = self
    /// authController.presentationContextProvider = self
    /// authController.performRequests()
    ///
    /// // Respond to the request.
    /// func authorizationController(controller: controller, didCompleteWithAuthorization: authorization) {
    ///  if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
    ///    // Take steps to handle the registration.
    ///    try await client.register(nickname: "Anne Johnson", clientDataJSON: credential.rawClientDataJSON, attestationObject: credential.rawAttestationObject, credentialId: credential.userID, headers: ["auth_session": "e5f6g7h8"])
    ///  }
    /// }
    ///
    /// func authorizationController(controller: controller, didCompleteWithError: error) {
    ///  // Handle the error.
    ///}
    ///
    /// ```
    public func register(nickname: String, clientDataJSON: Data, attestationObject: Data, credentialId: Data, headers: [String: String]) async throws {
        do {
            // Create the request.
            var (request, body) = try await createRegisterRequest(nickname: nickname, clientDataJSON: clientDataJSON, attestationObject: attestationObject, credentialId: credentialId)
            
            // Add additional headers if available.
            if var allHeaders = request.allHTTPHeaderFields {
                allHeaders.merge(headers) { (current, _) in current }
                request.allHTTPHeaderFields = allHeaders
            }
            
            // Submit the request and decode the response.
            let (data, response) = try await URLSession.shared.upload(for: request, from: body)
            
            // Check the response status for 200 range.
            guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
                throw String(decoding: data, as: UTF8.self)
            }
        }
        catch let error {
            throw String(error.localizedDescription)
        }
    }
    
    /// A request to present an attestation object containing a public key to the server for attestation verification and storage.
    /// - Parameters:
    ///   - nickname: The friendly name for the registration.
    ///   - clientDataJSON: Raw data that contains a JSON-compatible encoding of the client data.
    ///   - attestationObject: A data object that contains the returned attestation.
    ///   - credentialId: An identifier that the authenticator generates during registration to uniquely identify a specific credential.
    ///   - token: Represents an access token.
    ///
    /// An example request for registering a FIDO authenticator:
    ///
    /// ```
    /// // Register a new account on a service
    /// let client = RelyingPartyClient(baseURL: URL(string: "https://example.com")!)
    /// let token = try await client.authenticate(username: anne_johnson, password: "a1b2c3d4")
    ///
    /// // Obtain this from the server using client.challenge() based on return type.
    /// let result = try await client.challenge(token: token)
    ///
    /// let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider("example.com")
    /// let platformKeyRequest = platformProvider.createCredentialRegistrationRequest(challenge: result.challenge, name: result.user.name, userID: result.user.id)
    /// let authController = ASAuthorizationController([platformKeyRequest])
    /// authController.delegate = self
    /// authController.presentationContextProvider = self
    /// authController.performRequests()
    ///
    /// // Respond to the request.
    /// func authorizationController(controller: controller, didCompleteWithAuthorization: authorization) {
    ///  if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
    ///    // Take steps to handle the registration.
    ///    try await client.register(nickname: "anne_johnson", clientDataJSON: credential.rawClientDataJSON, attestationObject: credential.rawAttestationObject, credentialId: credential.userID, token: token)
    ///  }
    /// }
    ///
    /// func authorizationController(controller: controller, didCompleteWithError: error) {
    ///  // Handle the error.
    ///}
    /// ```
    public func register(nickname: String, clientDataJSON: Data, attestationObject: Data, credentialId: Data, token: Token) async throws {
        do {
            // Create the request.
            var (request, body) = try await createRegisterRequest(nickname: nickname, clientDataJSON: clientDataJSON, attestationObject: attestationObject, credentialId: credentialId)
            request.setValue(token.authorizationHeader, forHTTPHeaderField: "Authorization")
            
            // Submit the request and decode the response.
            let (data, response) = try await URLSession.shared.upload(for: request, from: body)
            
            // Check the response status for 200 range.
            guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
                throw String(decoding: data, as: UTF8.self)
            }
        }
        catch let error {
            throw String(error.localizedDescription)
        }
    }
    
    /// Creates and returns a`URLRequest` and the body as `Encodable` for an autheticator attestation registration.
    /// - Parameters:
    ///   - nickname: The friendly name for the registration.
    ///   - clientDataJSON: Raw data that contains a JSON-compatible encoding of the client data.
    ///   - attestationObject: A data object that contains the returned attestation.
    ///   - credentialId: An identifier that the authenticator generates during registration to uniquely identify a specific credential.
    ///   - token: Represents an access token.
    private func createRegisterRequest(nickname: String, clientDataJSON: Data, attestationObject: Data, credentialId: Data) async throws-> (URLRequest, Data) {
        // Create and encode the FIDO2 registration data.
        let registration = FIDO2Registration(nickname: nickname,
                                             clientDataJSON: clientDataJSON.base64UrlEncodedString(),
                                             attestationObject: attestationObject.base64UrlEncodedString(),
                                             credentialId: credentialId.base64UrlEncodedString())
        let body = try JSONEncoder().encode(registration)
        
        let url = baseURL.appendingPathComponent("/v1/register")
        
        // Set the request properties.
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        return (request, body)
    }
}
