# IBM Security Verify WebAuthn Relying Party Kit pour iOS

Proposez des solutions Apple Passkey à vos utilisateurs.

## Présentation


IBM Security Verify WebAuthn Relying Party Kit for iOS est le compagnon côté client d' [IBM Security Verify WebAuthn Relying Party Server for Swift](https://github.com/ibm-security-verify/webauthn-relying-party-server-swift) qui expose des API REST hébergées dans une image Docker.

RelyingPartyKit est un cadre léger qui permet aux utilisateurs existants d'enregistrer leur appareil avec Apple Passkey et de se connecter ensuite sans mot de passe, et aux nouveaux utilisateurs de s'inscrire et de valider leur compte.

Pour en savoir plus sur le développement d'applications compatibles avec Passkey, rendez-vous sur le [site Apple Developer](https://developer.apple.com/documentation/authenticationservices/connecting_to_a_service_with_passkeys).

### Mise en route

RelyingPartyKit est disponible en tant que paquet Swift Package Manager.  Pour l'utiliser, spécifiez le paquet comme dépendance dans votre projet Xcode ou votre fichier `Package.swift` :

```
.package(url: "https://github.com/ibm-security-verify/webauthn-relying-party-kit-ios.git")
```

## Contenu

### Permettre à un utilisateur de s'inscrire
Dans ce scénario, l'utilisateur n'existe pas dans votre système d'identité et doit posséder une adresse électronique pour être validé.

```
import RelyingPartyKit

// The baseURL is the host of the relying party server.
let client = RelyingPartyClient(baseURL: URL(string: "https://example.com")!)

// The result is an OTPChallenge to correlate the email sent to the email address.
let result = try await client.signup(name: "Anne Johnson", email: "anne_johnson@icloud.com")

// Use the result.transactionId and the OTP value generated in the email to validate. If successful, the returned Token can be used to register for Passkey.
let token = try await client.validate(transactionId: result.transactionId, otp: "123456")
```

### Authentification d'un utilisateur existant
Ce scénario permet d'authentifier un utilisateur existant à l'aide d'un nom d'utilisateur et d'un mot de passe.

```
import RelyingPartyKit

// The baseURL is the host of the relying party server.
let client = RelyingPartyClient(baseURL: URL(string: "https://example.com")!)

// The result is a Token which can be used to register for Passkey.
let token = try await client.authenticate(username: "anne_johnson@icloud.com", password: "a1b2c3d4")
```

### S'inscrire à Passkey
Ce scénario exige que l'utilisateur soit authentifié par une adresse `Token` valide.  L'authentification de l'utilisateur à l'aide de cookies est possible en utilisant le paramètre `headers` lorsque le serveur de la partie se fiant à l'authentification le prend en charge.  L'enregistrement de Passkey utilise [ASAuthorizationControllerDelegate](https://developer.apple.com/documentation/authenticationservices/asauthorizationcontrollerdelegate/) pour gérer le résultat de la demande d'enregistrement de la clé de plate-forme.

```
import RelyingPartyKit

// The baseURL is the host of the relying party server.
let client = RelyingPartyClient(baseURL: URL(string: "https://example.com")!)
let token = try await client.authenticate(username: "account@example.com", password: "a1b2c3d4")
let nickname = "Anne's iPhone"

// First generate a challenge from the relying party server.
let result: CredentialRegistrationOptions = try await client.challenge(displayName: nickname, token: token)

// Construct a request to the platform provider with the challenge. The challenge result contains the user identifier and name for Passkey registration.
let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: "example.com")
let request = provider.createCredentialRegistrationRequest(challenge: result.challenge,
    name: result.user.name,
    userID: result.user.id)
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

### Vérification d'un compte avec Passkey
Ce scénario concerne les utilisateurs qui ont déjà enregistré leur appareil à l'aide de Passkey. Comme pour l'enregistrement de Passkey, il utilise [ASAuthorizationControllerDelegate](https://developer.apple.com/documentation/authenticationservices/asauthorizationcontrollerdelegate/) pour gérer le résultat de la demande d'assertion de la clé de la plateforme.

```
import RelyingPartyKit

// The baseURL is the host of the relying party server.
let client = RelyingPartyClient(baseURL: URL(string: "https://example.com")!)

// First generate a challenge from the relying party server.
let result: CredentialAssertionOptions = try await client.challenge()

// Construct a request to the platform provider with the challenge.
let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: "example.com")
let request = provider.createCredentialAssertionRequest(challenge: result.challenge)
let controller = ASAuthorizationController(authorizationRequests: [request])
    controller.delegate = self
    controller.presentationContextProvider = self

// This will show the Passkey sheet for the user to continue with the registration and provides the outcome of the registration request on the ASAuthorizationControllerDelegate.
controller.performRequests()

// Respond to the request
func authorizationController(controller: controller, didCompleteWithAuthorization: authorization) {
    if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
        // Take steps to handle the assertion.
        let result: Token = try await client.signin(signature: credential.signature,
            clientDataJSON: credential.rawClientDataJSON,
            authenticatorData: credential.rawAuthenticatorData,
            credentialId: credential.credentialID,
            userId: credential.userID)
    } else {
        // Handle other authentication cases, such as Sign in with Apple.
    }
}
```

<!-- v2.3.5 : caits-prod-app-gp_webui_20241211T192242-1_en_fr -->