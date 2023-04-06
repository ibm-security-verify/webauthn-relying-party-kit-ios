# IBM Security Verify Relying Party Kit for iOS

Deliver Apple Passkey solutions to your users.

## Overview


The IBM Security Verify Relying Party Kit for iOS is the client-side companion to [IBM Security Verify Relying Party Server for Swift](https://github.com/ibm-security-verify/webauthn-relying-party-server) which exposes REST API's hosted in a Docker image. 

RelyingPartyKit is a lightweight framework that provides the ability for existing users to register their device with Apple Passkey and subsequently sign-in without a password and for new users to sign-up and validate their account.

Go to the [Apple Developer Site](https://developer.apple.com/documentation/authenticationservices/connecting_to_a_service_with_passkeys) if you like to learn more about developing Passkey-enabled apps.

### Getting started

RelyingPartyKit is available as a Swift Package Manager package.  To use it, specify the package as a dependency in your Xcode project or `Package.swift` file:

```
.package(url: "https://github.com/ibm-security-verify/relyingpartykit.git"),
```

## Contents

### Allowing a user to sign-up
This scenario is where the user doesn't exist in your identity system and requires ownership of an email address for validation.

```
import RelyingPartyKit

// The baseURL is the host of the relying party server.
let client = RelyingPartyClient(baseURL: URL(string: "https://example.com")!)

// The result is an OTPChallenge to correlate the email sent to the email address.
let result = try await client.signup(name: "Anne Johnson", email: "anne_johnson@icloud.com")

// Use the result.transactionId and the OTP value generated in the email to validate.   If successful, the returned Token can be used to register for Passkey.
let token = try await client.validate(transactionId: result.transactionId, otp: "123456")
```

### Authenticating an existing user
This scenario authenticates an existing user with a username and password.

```
import RelyingPartyKit

// The baseURL is the host of the relying party server.
let client = RelyingPartyClient(baseURL: URL(string: "https://example.com")!)

// The result is a Token which can be used to register for Passkey.
let token = try await client.authenticate(username: "anne_johnson@icloud.com", password: "a1b2c3d4")
```

### Registering for Passkey
This scenario requires the user to be authenticated with a valid `Token`. Registering for Passkey uses [ASAuthorizationControllerDelegate](https://developer.apple.com/documentation/authenticationservices/asauthorizationcontrollerdelegate/) to handle the result of the platform key registration request.

```
import RelyingPartyKit

// The baseURL is the host of the relying party server.
let client = RelyingPartyClient(baseURL: URL(string: "https://example.com")!)

let nickname = "Anne's iPhone"

// First generate a challenge from the relying party server.
let result = try await client.challenge(type: .attestation, displayName: nickname, token: token)
let challenge = result.challenge.base64UrlEncodedStringWithPadding
let userId = Data(base64Encoded: result.userId!.base64UrlEncodedStringWithPadding)!

// Construct a request to the platform provider with the challenge. The challenge result contains the user identifier and name for Passkey registration.
let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: "example.com")
let request = provider.createCredentialRegistrationRequest(challenge: Data(base64Encoded: challenge)!, 
    name: result.name!,
    userID: userId
let controller = ASAuthorizationController(authorizationRequests: [request])
    controller.delegate = self
    controller.presentationContextProvider = self

// This will display the Passkey sheet for the user to continue with the registration.  The outcome of the registration request is provided on the ASAuthorizationControllerDelegate.
controller.performRequests()

// Respond to the request
func authorizationController(controller: controller, didCompleteWithAuthorization: authorization) {
    if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
        // Take steps to handle the registration.
        try await client.register(nickname: nickname,
            clientDataJSON: credential.rawClientDataJSON,
            attestationObject: credential.rawAttestationObject!,
            credentialId: credential.credentialID,
            token: token)
    } else {
        // Handle other authentication cases, such as Sign in with Apple.
    }
}
```

### Verifying an account with Passkey
This scenario is for users who have previously registered their device using Passkey. Similar to registering for Passkey, it uses [ASAuthorizationControllerDelegate](https://developer.apple.com/documentation/authenticationservices/asauthorizationcontrollerdelegate/) to handle the result of the platform key assertion request.

```
import RelyingPartyKit

// The baseURL is the host of the relying party server.
let client = RelyingPartyClient(baseURL: URL(string: "https://example.com")!)

// First generate a challenge from the relying party server.
let result = try await client.challenge(type: .assertion)
let challenge = result.challenge.base64UrlEncodedStringWithPadding

// Construct a request to the platform provider with the challenge.
let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: "example.com")
let request = provider.createCredentialAssertionRequest(challenge: Data(base64Encoded: challenge)!)
let controller = ASAuthorizationController(authorizationRequests: [request])
    controller.delegate = self
    controller.presentationContextProvider = self

// This will show the Passkey sheet for the user to continue with the registration and provides the outcome of the registration request on the ASAuthorizationControllerDelegate.
controller.performRequests()


// Respond to the request
func authorizationController(controller: controller, didCompleteWithAuthorization: authorization) {
    if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
        // Take steps to handle the assertion.
        client.signin(signature: credential.signature,
            clientDataJSON: credential.rawClientDataJSON,
            authenticatorData: credential.rawAuthenticatorData,
            credentialId: credential.credentialID,
            userId: credential.userID)
    } else {
        // Handle other authentication cases, such as Sign in with Apple.
    }
}
```
