//
// Copyright contributors to the IBM Security Verify Relying Party Kit for iOS project
//

import Foundation

/// WebAuthn credential options that represents a response to a client's request for generation of a new attestation or assertion.
public protocol CredentialsOptions {
    /// A time, in milliseconds, that the Relying Party is willing to wait for the call to complete.
    var timeout: Int {
        get
    }
    
    /// A challenge that is signed along with other data, when registering or authenticating an authenticator.
    var challenge: Data {
        get
    }
}

/// A structure representing a WebAuthn [PublicKeyCredentialCreationOptions](https://w3c.github.io/webauthn/#dictionary-makecredentialoptions).
public struct CredentialRegistrationOptions: CredentialsOptions, Codable {
    public let challenge: Data
    public let timeout: Int
    
    /// Contains a name and an identifier for the Relying Party responsible for the request.
    public let rp: Rp
    
    /// Contains names and an identifier for the user account performing the registration.
    public let user: User
    
    /// A list any existing credentials mapped to this user account (as identified by `user.id`).
    public let excludeCredentials: [ExcludeCredential]?
    
    /// The capabilities and settings that the authenticator.
    public let authenticatorSelection: AuthenticatorSelection?
    
    /// A list of key types and signature algorithms the Relying Party supports, ordered from most preferred to least preferred.
    public let pubKeyCredParams: [PubKeyCredParam]
    
    /// Additional processing containing the client extension input.
    public let extensions: Extension?
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
       
        // Assign the properties, converting the id as Base64 URL encoded data.
        let challenge = try container.decode(String.self, forKey: .challenge).base64UrlEncodedStringWithPadding
        self.challenge = Data(base64Encoded: challenge)!
        
        self.timeout = try container.decode(Int.self, forKey: .timeout)
        self.rp = try container.decode(Rp.self, forKey: .rp)
        self.user = try container.decode(User.self, forKey: .user)
        self.excludeCredentials = try container.decodeIfPresent([ExcludeCredential].self, forKey: .excludeCredentials) ?? []
        self.authenticatorSelection = try? container.decodeIfPresent(AuthenticatorSelection.self, forKey: .authenticatorSelection)
        self.pubKeyCredParams = try container.decode([PubKeyCredParam].self, forKey: .pubKeyCredParams)
        self.extensions = try container.decodeIfPresent(Extension.self, forKey: .extensions)
    }
    
    /// The name and identifier for the user account performing the registration.
    public struct User: Codable {
        /// An identifier for a user account.
        public let id: Data
        
        /// A human-palatable name for the entity.
        public let name: String
        
        /// A human-palatable name for the user account, intended only for display.
        public let displayName: String
        
        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            
            // Assign the properties, converting the id as Base64 URL encoded data.
            let id = try container.decode(String.self, forKey: .id).base64UrlEncodedStringWithPadding
            self.id = Data(base64Encoded: id)!
            
            self.name = try container.decode(String.self, forKey: .name)
            self.displayName = try container.decode(String.self, forKey: .displayName)
        }
    }
    
    /// The capabilities and settings that the authenticator.
    public struct AuthenticatorSelection: Codable {
        /// Eligible authenticators are filtered to be only those authenticators attached with the specified authenticator attachment modality.  i.e `platform` or `cross-platform`.
        public let authenticatorAttachment: String
        
        /// The extent to which the Relying Party desires to create a client-side discoverable credential. i.e `discouraged`, `preferred` or `required`.
        public let residentKey: String
        
        /// Whether registration requires a resident key.
        public let requireResidentKey: Bool
        
        /// Specifies the Relying Party's requirements regarding user verification.  i.e `discouraged`, `preferred` or `required`.
        public let userVerification: String
    }
    
    /// The key type and signature algorithm the Relying Party supports, ordered from most preferred to least preferred.
    public struct PubKeyCredParam: Codable {
        /// A number identifying a cryptographic algorithm
        public let alg: Int
        
        /// The type of credential to be created.
        public let type: String
    }

    /// The identifier and type of an existing credentials mapped to a user account.
    public struct ExcludeCredential: Codable {
        /// contains the credential ID
        public  let id: String

        /// The type of the public key credential
        public let type: String
    }
    
    /// The name and identifier for the Relying Party responsible for the request.
    public struct Rp: Codable {
        /// A unique identifier for the Relying Party entity.
        public let id: String
        
        /// A human-palatable name for the Relying Party entity.
        public let name: String
    }
    
    /// Additional processing containing the client extension input.
    public struct Extension: Codable {
    }
}

/// A structure representing a WebAuthn [PublicKeyCredentialRequestOptions)](https://w3c.github.io/webauthn/#dictdef-publickeycredentialrequestoptions).
public struct CredentialAssertionOptions: CredentialsOptions, Codable {
    public let challenge: Data
    public let timeout: Int
    
    /// Specifies the RP ID claimed by the Relying Party.
    public let rpId: String
    
    /// A list used by the client to find authenticators eligible for this authentication ceremony.
    public let allowCredentials: [AllowCredential]?
    
    /// Additional processing containing the client extension input.
    public let extensions: Extension?
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
       
        // Assign the properties, converting the id as Base64 URL encoded data.
        let challenge = try container.decode(String.self, forKey: .challenge).base64UrlEncodedStringWithPadding
        self.challenge = Data(base64Encoded: challenge)!
        
        self.rpId = try container.decode(String.self, forKey: .rpId)
        self.timeout = try container.decode(Int.self, forKey: .timeout)
        self.allowCredentials = try container.decodeIfPresent([AllowCredential].self, forKey: .allowCredentials) ?? []
        self.extensions = try container.decodeIfPresent(Extension.self, forKey: .extensions)
    }
    
    /// The identifier and type of an existing credentials mapped to a user account.
    public struct AllowCredential: Codable {
        /// Contains the credential ID
        public let id: String

        /// The type of the public key credential
        public let type: String
    }
    
    /// Additional processing containing the client extension input.
    public struct Extension: Codable {
    }
}

/// A structure representing a FIDO2 registration.
struct FIDO2Registration: Encodable {
    /// The friendly name for the registration.
    let nickname: String
    
    /// The base64Url-encoded clientDataJSON that is received from the WebAuthn client.
    let clientDataJSON: String
    
    /// The base64Url-encoded attestationObject that is received from the WebAuthn client.
    let attestationObject: String
    
    /// The credential identifier that is received from the WebAuthn client.
    ///
    /// The string is Base64 URL encoded with URL safe characters.
    let credentialId: String
}

/// A structure representing a FIDO2 verification.
struct FIDO2Verification: Encodable {
    /// The base64Url-encoded clientDataJson that was received from the WebAuthn client.
    let clientDataJSON: String
    
    /// Information about the authentication that was produced by the authenticator and verified by the signature.
    let authenticatorData: String
    
    /// The credential identifier that is received from the WebAuthn client.
    ///
    /// The string is Base64 URL encoded with URL safe characters.
    let credentialId: String
    
    /// The base64Url-encoded bytes of the signature of the challenge data that was produced by the authenticator.
    let signature: String
    
    /// The userId provided when creating this credential.
    let userHandle: String
}
