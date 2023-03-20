//
// Copyright contributors to the IBM Security Verify Relying Party Kit for iOS project
//

import Foundation

extension String: LocalizedError {
    public var errorDescription: String? {
        return self
    }
    
    /// Represents a Base-64 URL encoded string  as defined in [RFC4648](https://tools.ietf.org/html/rfc4648) with padding.
    public var base64UrlEncodedStringWithPadding: String {
        var value = replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        if value.count % 4 > 0 {
            value.append(String(repeating: "=", count: 4 - value.count % 4))
        }
        
        return value
    }
}
