//
// Copyright contributors to the IBM Security Verify Relying Party Kit for iOS project
//

import Foundation

/// The type of FIDO2 challenge.
public enum ChallengeType: String, Codable {
    /// To attest to the provenance of an authenticator.
    case attestation
    
    /// To assert a cryptographically signed object returned by an authenticator.
    case assertion
}

/// A structure that represents a WebAuthn challenge request.
///
/// This structure is used for both registration (attetation) and sign-in (assertion) requests.
struct ChallengeRequest: Encodable {
    /// The display name used by the authenticator for UI representation.
    let displayName: String?
    
    /// The type of FIDO2 challenge.
    let type: ChallengeType
}

/// A structure representing a FIDO2 challenge.
public struct FIDO2Challenge: Decodable {
    /// The unique challenge that is used as part of this attestation or assertion attempt.
    public let challenge: String
    
    /// The unique identifier of the user account.
    public let userId: String
    
    /// The name of the user requesting the challenge.
    public let name: String
    
    /// The display name of the user requesting the challenge.
    public let displayName: String
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
