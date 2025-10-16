---
title: "Remote Attestation with Exported Authenticators"
abbrev: "Application Layer Attestation"
category: std

docname: draft-fossati-tls-exported-attestation-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: Security
workgroup: TLS
keyword:
 - Attestation
 - TLS
 - Exported Authenticators
venue:
  group: tls
  type: Working Group
  mail: tls@ietf.org
  arch: https://datatracker.ietf.org/wg/tls/about/
  github: "tls-attestation/exported-attestation"
  latest: "https://tls-attestation.github.io/exported-attestation/draft-fossati-tls-exported-attestation.html"

author:
  -
    name: Thomas Fossati
    organization: Linaro
    email: thomas.fossati@linaro.org
  -
    name: Muhammad Usama Sardar
    organization: TU Dresden
    email: muhammad_usama.sardar@tu-dresden.de
  -
    fullname: Tirumaleswar Reddy
    organization: Nokia
    city: Bangalore
    region: Karnataka
    country: India
    email: "k.tirumaleswar_reddy@nokia.com"
  -
    name: Yaron Sheffer
    organization: Intuit
    email: yaronf.ietf@gmail.com
  -
    name: Hannes Tschofenig
    organization: University of Applied Sciences Bonn-Rhein-Sieg
    abbrev: H-BRS
    country: Germany
    email: Hannes.Tschofenig@gmx.net
  -
    name: Ionut Mihalcea
    organization: Arm Limited
    email: ionut.mihalcea@arm.com


normative:
  RFC9334:
  RFC9261:
  RFC2119:
  RFC8174:
  RFC9261:
  RFC8446: tls13
  I-D.ietf-rats-msg-wrap:
  I-D.ietf-tls-tlsflags:
  I-D.bft-rats-kat:


informative:
  I-D.ietf-lamps-csr-attestation:
  TLS-Ext-Registry:
     author:
        org: IANA
     title: Transport Layer Security (TLS) Extensions
     target: https://www.iana.org/assignments/tls-extensiontype-values
     date: November 2023

--- abstract


This specification defines a method for two parties in a communication interaction to exchange Evidence and Attestation Results using exported authenticators, as defined in RFC 9261. Additionally, it introduces the `cmw_attestation` extension, which allows attestation credentials to be included directly in the Certificate message sent during the Exported Authenticator-based post-handshake authentication. The approach supports both the passport and background check models from the RATS architecture while ensuring that attestation remains bound to the underlying communication channel.

--- middle

# Introduction

There is a growing need to demonstrate to a remote party that cryptographic keys are stored in a secure element, the device is in a known good state, secure boot has been enabled, and that low-level software and firmware have not been tampered with. Remote attestation provides this capability.

More technically, an Attester produces a signed collection of Claims that constitute Evidence about its running environment(s). A Relying Party may consult an Attestation Result produced by a Verifier that has appraised the Evidence to make policy decisions regarding the trustworthiness of the Target Environment being assessed. This is, in essence, what RFC 9334 {{RFC9334}} defines.

At the time of writing, several standard and proprietary remote attestation technologies are in use. This specification aims to remain as technology-agnostic as possible concerning implemented remote attestation technologies. To streamline attestation in TLS, this document introduces the cmw_attestation extension, which allows attestation credentials to be conveyed directly in the Certificate message during the Exported Authenticator-based post-handshake authentication. This eliminates reliance on real-time certificate issuance from a Certificate Authority (CA), reducing handshake delays while ensuring Evidence remains bound to the TLS session. The extension supports both the passport and background check models from the RATS architecture, enhancing flexibility for different deployment scenarios.

This document builds upon three foundational specifications:

- RATS (Remote Attestation Procedures) Architecture {{RFC9334}}: RFC 9334 defines how remote attestation systems establish trust between parties by exchanging Evidence and Attestation Results. These interactions can follow different models, such as the passport or the background check model, depending on the order of data flow in the system.

- TLS Exported Authenticators {{RFC9261}}: RFC 9261 offers bi-directional, post-handshake authentication. Once a TLS connection is established, both peers can send an authenticator request message at any point after the handshake. This message from the server and the client uses the CertificateRequest and the ClientCertificateRequest messages, respectively. The peer receiving the authenticator request message can respond with an Authenticator consisting of Certificate, CertificateVerify, and Finished messages. These messages can then be validated by the other peer.

- RATS Conceptual Messages Wrapper (CMW) {{I-D.ietf-rats-msg-wrap}}: CMW provides a structured encapsulation of Evidence and Attestation Result payloads, abstracting the underlying attestation technology.


This specification introduces the cmw_attestation extension, enabling Evidence to be included directly in the Certificate message during the Exported Authenticator-based post-handshake authentication defined in {{RFC9261}}.

# Terminology

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, NOT RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals as shown here.

The reader is assumed to be familiar with the vocabulary and concepts defined in RFC 9334 and RFC 9261.

"Remote attestation credentials", or "attestation credentials", is used to refer to both Evidence and attestation results, when no distinction needs to be made between them.

# cmw_attestation Extension to the Authenticator's Certificate message

This document introduces a new extension, called `cmw_attestation`, to the Authenticator's Certificate message.
This extension allows Evidence or Attestation Results to be included in the extensions field of the end-entity certificate in the TLS Certificate message.

As defined in {{Section 4.4.2 of -tls13}}, the TLS Certificate message consists of a certificate_list, which is a sequence of CertificateEntry structures. Each CertificateEntry contains a certificate and a set of associated extensions. The cmw_attestation extension MUST appear only in the first CertificateEntry of the Certificate message and applies exclusively to the end-entity certificate. It MUST NOT be included in entries corresponding to intermediate or trust anchor certificates. This design ensures that attestation information is tightly bound to the entity being authenticated.

The cmw_attestation extension is only included in the Certificate message during Exported Authenticator-based post-handshake authentication. This ensures that the attestation credentials are conveyed within the Certificate message, eliminating the need for modifications to the X.509 certificate structure.

~~~
struct {
    opaque cmw_data<1..2^16-1>;
} CMWAttestation;
~~~

cmw_data: Encapsulates the attestation credentials in CMW format {{I-D.ietf-rats-msg-wrap}}. The cmw_data field is encoded using CBOR or JSON.

This approach eliminates the need for real-time certificate issuance from a Certificate Authority (CA) and minimizes handshake delays. Typically, CAs require several seconds to minutes to issue a certificate due to verification steps such as validating subject identity, signing the certificate, and distributing it. These delays introduce latency into the TLS handshake, making real-time certificate generation impractical. The cmw_attestation extension circumvents this issue by embedding attestation data within the Certificate message itself, removing reliance on external certificate issuance processes.

## Negotiation of cmw_attestation Extension

Clients and servers use the TLS flags extension defined in {{I-D.ietf-tls-tlsflags}} to indicate support for the functionality defined in this document. We refer to flag corresponding to the "cmw_attestation" extension as the "CMW_Attestation" flag.

The "CMW_Attestation" flag proposed by the client in the ClientHello MUST be acknowledged in the EncryptedExtensions if the server also  supports the functionality defined in this document and is configured to use it.

If the "CMW_Attestation" flag is not set, servers ignore any of the functionality specified in this document, and attestation credentials cannot be conveyed using "Exported TLS Authenticators".

## Usage in Post-Handshake Authentication

The `cmw_attestation` extension is designed to be used exclusively in post-handshake authentication as defined in {{RFC9261}}. It allows attestation credentials to be transmitted in the Authenticator's Certificate message only in response to an Authenticator Request. This ensures that attestation credentials are provided on demand rather than being included in the initial TLS handshake.

To maintain a cryptographic binding between the Evidence and the authentication request, the `cmw_attestation` extension MUST be associated with the `certificate_request_context` of the corresponding CertificateRequest or ClientCertificateRequest message (from the Server or Client, respectively). This binding ensures that:

- The Evidence is specific to the authentication event and cannot be replayed across different TLS sessions.
- The Evidence remains tied to the cryptographic context of the TLS session.

## Ensuring Compatibility with X.509 Certificate Validation

The `cmw_attestation` extension does not modify or replace X.509 certificate validation mechanisms. It serves as an additional source of authentication data rather than altering the trust model of PKI-based authentication. Specifically:

- Certificate validation (e.g., signature verification, revocation checks) MUST still be performed according to TLS {{-tls13}} and PKIX {{!RFC5280}}.
- The attestation credentials carried in `cmw_attestation` MUST NOT be used as a substitute for X.509 certificate validation but can be used alongside standard certificate validation for additional security assurances. See {{key-prot}} for more information regarding the assurances linking attestation credentials and X.509 certificates.
- Implementations MAY reject connections where the certificate is valid but the attestation credentials is missing or does not meet security policy.

## Applicability to Client and Server Authentication

The `cmw_attestation` extension is applicable to both client and server authentication in Exported Authenticator-based post-handshake authentication.

In TLS, one party acts as the Relying Party, and the other party acts as the Attester. Either the client or the server may fulfill these roles depending on the authentication direction.

The Attester may respond with either:

- Evidence (Background Check Model):
  - The Attester generates Evidence and includes it in the `cmw_attestation` extension to the Authenticator's Certificate message.
  - The Relying Party forwards the Evidence to an external Verifier for evaluation and waits for an Attestation Result.
  - The Relying Party grants or denies access, or continues or terminates the TLS session, based on the Verifier's Attestation Result.

- Attestation Result (Passport Model):
  - The Attester sends Evidence to a Verifier beforehand.
  - The Verifier issues an Attestation Result to the Attester.
  - The Attester includes the Attestation Result in the `cmw_attestation` extension to the Authenticator's Certificate message and sends it to the Relying Party.
  - The Relying Party validates the Attestation Result directly without needing to contact an external Verifier.

By allowing both Evidence and Attestation Results to be conveyed within `cmw_attestation`, this mechanism supports flexible attestation workflows depending on the chosen trust model.

# Architecture

The `cmw_attestation` extension enables attestation credentials to be included in the Certificate message during Exported Authenticator-based post-handshake authentication, ensuring that attestation remains bound to the TLS session.

However, applications using this mechanism still need to negotiate the encoding format (e.g., JOSE or COSE) and specify how attestation credentials are processed. This negotiation can be done via application-layer signaling or predefined profiles. Future specifications may define mechanisms to streamline this negotiation.

Upon receipt of a Certificate message containing the `cmw_attestation` extension, an endpoint MUST take the following steps to validate the attestation credentials:

- Background Check Model:
  - Verify Integrity and Authenticity: The Evidence must be cryptographically verified against a known trust anchor, typically provided by the hardware manufacturer.
  - Ensure Certificate Binding and Freshness: The Evidence must be explicitly associated with the `certificate_request_context` in the authenticator request to ensure relevance, freshness, and protection against replay.
  - Evaluate Security Policy Compliance: The Evidence must be evaluated against the Relying Party's security policies to determine if the attesting device and the private key storage meet the required criteria.

- Passport Model:
  - Verify the Attestation Result: The Relying Party MUST check that the Attestation Result is correctly signed by the issuing authority and that it meets the Relying Party’s security requirements.

By integrating `cmw_attestation` directly into the Certificate message during Exported Authenticator-based post-handshake authentication, this approach reduces latency and complexity while maintaining strong security guarantees.

In the following examples, the server possesses an identity certificate, while the client is not authenticated during the initial TLS exchange.

{{fig-passport}} shows the passport model while {{fig-background}} illustrates the background-check model.

~~~aasvg
Client                   Server                   Verifier
  |                        |                         |
  |  Regular TLS Handshake |                         |
  |    (Server-only auth)  |                         |
  |<---------------------->|                         |
  |                        |                         |
  |  ... time passes ...   |                         |
  |                        |                         |
  | Authenticator Request  |                         |
  | (ClientCertificateReq) |                         |
  |<-----------------------|                         |
  |                        |                         |
  |                  Sends Evidence                  |
  |------------------------------------------------->|
  |                 Gets Attestation result          |
  |<-------------------------------------------------|
  | Exported Authenticator(|                         |
  | Certificate with       |                         |
  | cmw_attestation,       |                         |
  | CertificateVerify,     |                         |
  | Finished)              |                         |
  |----------------------->|                         |
~~~
{: #fig-passport title="Passport Model with Client as Attester"}

{{fig-background}} shows an example using the background-check model.

~~~aasvg
Client              Attester                 Server           Verifier
  |                   |                        |                  |
  |  Regular TLS Handshake (Server-only auth)  |                  |
  |<------------------------------------------>|                  |
  |                   |                        |                  |
  |   ... time passes ...                      |                  |
  |                   |                        |                  |
  | Authenticator Request (ClientCertReq)      |                  |
  |<-------------------------------------------|                  |
  |                   |                        |                  |
  | Request Evidence  |                        |                  |
  |------------------>|                        |                  |
  | Attestation       |                        |                  |
  | Evidence          |                        |                  |
  |<------------------|                        |                  |
  | Exported Authenticator(Certificate with    |                  |
  | cmw_attestation                            |                  |
  | CertificateVerify,                         |                  |
  | Finished)                                  |                  |
  |------------------------------------------->|                  |
  |                   |                        | Send Evidence    |
  |                   |                        |----------------->|
  |                   |                        | Attestation      |
  |                   |                        | Result           |
  |                   |                        |<-----------------|
  |                   |                        |                  |
~~~
{: #fig-background title="Background Check Model with a Separate Client-Side Attester"}

## API Requirements for Attestation Support

To enable attestation workflows, implementations of the Exported Authenticator API MUST support the following:

1. Authenticator Generation
   - The API MUST support the inclusion of attestation credentials within the Certificate message provided as input.

2. Context Retrieval
   - The certificate_request_context MUST be provided in all cases to ensure proper validation of Evidence.
   - The receiving endpoint MUST use the "get context" API to retrieve the `certificate_request_context` associated with the exported authenticator as attestation-based authentication requires strict enforcement of the request context. This ensures that the freshness of Evidence can be verified.

3. Authenticator Validation
   - The API MUST verify that the Evidence within the Certificate message is cryptographically valid and bound to the certificate_request_context.


# Security Considerations

This document inherits the security considerations of RFC 9261 and RFC 9334. The integrity of the exported authenticators must be guaranteed, and any failure in validating Evidence SHOULD be treated as a fatal error in the communication channel. Additionally, in order to benefit from remote attestation, Evidence MUST be protected using dedicated attestation keys chaining back to a trust anchor. This trust anchor will typically be provided by the hardware manufacturer.

## Using the TLS Connection

Remote attestation in this document occurs within the context of a TLS handshake, and the TLS connection
remains valid after this process. Care must be taken when handling this TLS connection, as both the client
and server must agree that remote attestation was successfully completed before exchanging data with the
attested party.

Session resumption presents special challenges since it happens at the TLS level, which is not aware of the
application-level Authenticator. The application (or the modified TLS library) must ensure that a resumed
session has already completed remote attestation before the session can be used normally, and race conditions are possible.

## Evidence Freshness

The Evidence carried in cmw_attestation does not require an additional freshness mechanism, such as a nonce or timestamp, since freshness is inherently provided by the certificate_request_context in the authenticator request.

The evidence presented in this protocol is valid only at the time it is generated and presented. To ensure that the attested peer remains in a secure state, remote attestation may be re-initiated periodically. In the current protocol, this can be achieved by initiating a new Exported Authenticator-based post-handshake authentication exchange, which will generate a new certificate_request_context to maintain freshness.

## Protection of handshake signing key {#key-prot}

The use of remote attestation in the context of this document extends to the establishment of trustworthiness for the key in the Certificate message. This can apply to certificate generation for this key, but more importantly to its use in the Exported Authenticator-based authentication.

In certain deployments it is expected that the Hardware Security Module (HSM) or Trusted Execution Environment (TEE) is responsible for generating the key pair and producing attestation credentials, which are included in the Certificate Signing Request (CSR) as defined in {{I-D.ietf-lamps-csr-attestation}}. This attestation enables the CA to verify that the private key is securely stored and that the platform meets the required security standards before issuing a certificate.

During the Exported Authenticator-based authentication exchange, the attestation credential MUST convey enough context relating to how the key in the Certificate message is protected. Conveyance can be either explicit (e.g., through the use of the key attestation mechanisms defined in {{I-D.bft-rats-kat}}), or implicit by relying on properties of the code which handles the Exported Authenticator-based exchange.

# IANA Considerations

## TLS Extension Type Registration

IANA is requested to register the following new extension type in the "TLS ExtensionType Values" registry:

| Value | Extension Name    | TLS 1.3 | DTLS 1.3 | Recommended | Reference      |
|-------|-------------------|---------|----------|-------------|----------------|
| TBD   | cmw_attestation   | CT      | Y        | Yes         | This Document  |


## TLS Flags Extension Registry

IANA is requested to add the following entry to the "TLS Flags" extension registry
[TLS-Ext-Registry]:

- Value: TBD1
- Flag Name: CMW_Attestation
- Messages: CH, EE
- Recommended: Y
- Reference: [This document]

--- back

# Acknowledgements
We would like to thank Chris Patton for his proposal to explore RFC 9261 for attested TLS.
We would also like to thank Paul Howard and Yogesh Deshpande for their input.
