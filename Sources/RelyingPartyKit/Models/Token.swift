//
// Copyright contributors to the IBM Security Verify Relying Party Kit for iOS project
//

import Foundation

/// Represents an access token.
public struct Token: Codable {
    /// The access token that is issued by the authorization server.
    public let accessToken: String
    
    /// The type of the access token.
    ///
    /// Default is `Bearer`.
    public let tokenType: String
    
    /// The lifetime, in seconds, of the access token.
    ///
    /// Default is `3600`.
    public let expiry: Int
    
    /// An artifact that proves that the user has been authenticated.
    ///
    /// Default is `nil`.
    public let idToken: String?
    
    
    /// The HTTP authorization header value for requests to an OpenID Connect service.
    ///
    /// The value combines the `tokenType` and `accessToken` as follows:
    /// ```
    /// Bearer a1b2c3d4
    /// ```
    public var authorizationHeader: String {
        return "\(tokenType) \(accessToken)"
    }
    
    private enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiry = "expires_in"
        case idToken = "id_token"
    }
}
