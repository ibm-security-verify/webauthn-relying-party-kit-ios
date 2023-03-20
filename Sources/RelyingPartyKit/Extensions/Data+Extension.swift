//
// Copyright contributors to the IBM Security Verify Relying Party Kit for iOS project
//

import Foundation

extension Data {
    /// Returns a Base-64 URL encoded string.
    /// - Remark: Base-64 URL encoded string removes instances of `=`  and replaces `+` with `-` and `/` with `_`.
    func base64UrlEncodedString() -> String {
        return self.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
