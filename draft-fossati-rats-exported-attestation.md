---
title: "Remote Attestation with Exported Authenticators"
abbrev: "Remote Attestation with Exported Authenticators"
category: std

docname: draft-fossati-rats-exported-attestation-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - Attestation
 - TLS
 - Key Attestation
 - Exported Authenticators
venue:
  group: LAMPS
  type: Working Group
  mail: tls@ietf.org
  arch: https://datatracker.ietf.org/wg/rats/about/
#  github: "ietf-rats-wg/app-layer-attestation"
#  latest: "https://ietf-rats-wg.github.io/draft-fossati-rats-app-layer-attestation/draft-fossati-rats-app-layer-attestation.html"

author:
  -
    name: Thomas Fossati
    organization: Linaro
    email: thomas.fossati@linaro.org
  -
    name: Muhammad Usama Sardar
    organization: TU Dresden
    email: muhammad_usama.sardar@tu-dresden.de
  - name: Hannes Tschofenig
    organization: University of Applied Sciences Bonn-Rhein-Sieg
    abbrev: H-BRS
    country: Germany
    email: Hannes.Tschofenig@gmx.net

normative:
  RFC9334:
  RFC9261:
  RFC2119:
  RFC8174:
  RFC9261:

informative:
  I-D.ietf-lamps-csr-attestation:
  I-D.ietf-lamps-attestation-freshness:

--- abstract

This specification defines a method for two parties in a communication interaction to exchange attestation evidence and attestation results using exported authenticators, as defined in RFC 9261. This approach falls into the category of post-handshake attestation by exchanging payloads in the application layer protocol while binding the remote attestation to the underlying communication channel. This document supports both the passport and background check models from the RATS architecture.

--- middle

# Introduction

There is a growing need to demonstrate to a remote party that cryptographic keys are stored in a secure element, the device is in a known good state, secure boot has been enabled, and that low-level software and firmware have not been tampered with. Remote attestation provides this capability.

More technically, an Attester produces a signed collection of Claims that constitute Evidence about its running environment(s). A Relying Party may consult an Attestation Result produced by a Verifier that has appraised the Evidence to make policy decisions regarding the trustworthiness of the Target Environment being assessed. This is, in essence, what RFC 9334 defines.

At the time of writing, several standard and proprietary remote attestation technologies are in use. This specification aims to remain as technology-agnostic as possible concerning implemented remote attestation technologies. As a result, this document focuses on the conveyance of Evidence and Attestation Results as part of the payloads defined by Exported Authenticators. The end-entity certificate is associated with key material that serves as an Attestation Key, which acts as Evidence originating from the Attester.

This document builds upon two foundational specifications:

- RATS Architecture {{RFC9334}}: The RATS (Remote Attestation Procedures) architecture defines how remote attestation systems establish trust between parties by exchanging attestation evidence and results. These interactions can follow different models, such as the passport or background check model, depending on the role of a verifier in the system.

- TLS Exported Authenticators {{RFC9261}}: TLS Exported Authenticators are structured messages that can be exported by either party in a TLS connection and validated by the other party. Once a TLS connection is established, an authenticator message can be constructed to prove possession of a certificate and its corresponding private key. The mechanisms described in this document focus primarily on the server's ability to generate TLS Exported Authenticators. Each authenticator is computed using a Handshake Context and Finished MAC Key derived from the TLS session. The Handshake Context is the same for both parties, but the Finished MAC Key differs depending on whether the authenticator is created by the client or the server. Verified authenticators result in the validation of certificate chains and confirmed possession of the private key. These certificates can be integrated into a collection of available certificates, and desired certificates can also be described within these collections.

This specification reuses exported authenticators to carry attestation evidence and/or attestation results. While exported authenticators traditionally deal with certificates, in this document, we use them for key attestation. Consequently, this mechanism applies specifically to remote attestation technologies that offer key attestation, though the encoding format is not restricted to X.509 certificates.

# Terminology

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, NOT RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals as shown here.

The reader is assumed to be familiar with the vocabulary and concepts defined in RFC 9334 and RFC 9261.

We use the term REMOTE_ATTESTATION payload to refer to the opaque token generated by the TLS Exported Authenticator implementation. The content is opaque to the application layer protocol but, of course, not to the TLS Exported Authenticator implementation.

# Architecture

Designers of application layer protocols need to define payload formats for conveying exported authenticators that contain remote attestation evidence. They must also provide mechanisms to inform both communication partners of their ability to exchange attestation evidence and results via this specification. This capability can be specified in a profile of this document or dynamically negotiated during protocol exchanges.

The Exported Authenticator API defined in RFC 9261 accepts a request, a set of certificates, and supporting information as input. The output is an opaque token that serves as the REMOTE_ATTESTATION payload. Upon receipt of a REMOTE_ATTESTATION payload, an endpoint that supports secondary certificates MUST take the following steps to validate the contained token:

Use the get context API to retrieve the certificate_request_context that was used to generate the authenticator (if any). Since the certificate_request_context for spontaneous server certificates is chosen by the server, its usage is implementation-dependent (see Section 5 of {{RFC9261}} for more details).
Use the validate API to confirm the authenticator’s validity with respect to the generated request (if any). If validation fails, this SHOULD be treated as a connection error. Upon successful validation, the endpoint can conduct further checks to ensure the certificate’s acceptability.

In this example, the server possesses an identity certificate, while the client is not authenticated during the initial TLS exchange. For readability purposes the CA and the Verifier are combined into a single entity. For a specific instantiation of the example exchange consider the integration of {{I-D.ietf-lamps-csr-attestation}} and {{I-D.ietf-lamps-attestation-freshness}}.

~~~aasvg
Client                   Server                  CA/Verifier
  |                        |                         |
  |------------------------|                         |
  |  Regular TLS Handshake |                         |
  |    (Server-only auth)  |                         |
  |------------------------|                         |
  |                        |                         |
  |  ... time passes ...   |                         |
  |                        |                         |
  |                        |                         |
  |<-----------------------|                         |
  | Exported Authenticator |                         |
  | (ClientCertificateReq) |                         |
  |------------------------|                         |
  |                        |                         |
  |<------------------------------------------------>| 
  |      Certificate Management Protocol (CSR)       |
  |       (Attestation evidence requested)           |
  |                        |                         |
  |<-------------------------------------------------|
  |      Certificate       |                         |
  | (Attestation Evidence) |                         |
  |                        |                         |
  |------------------------|                         |
  | Exported Authenticator |                         |
  |  (Authenticator with   |                         |
  |   Attestation Result)  |                         |
  |------------------------|                         |
  |                        |                         |
~~~
{: #fig-passport title="Passport Model with Client as Attester"}

~~~aasvg
Client              Attester                 Server           Verifier
  |                   |                        |                  |
  |<------------------------------------------>|                  |
  |  Regular TLS Handshake (Server-only auth)  |                  |
  |                   |                        |                  |
  |   ... time passes ...                      |                  |
  |                   |                        |                  |
  |<-------------------------------------------|                  |
  | Exported Authenticator (ClientCertReq), Nonce                 |
  |                   |                        |                  |
  |------------------>|                        |                  |
  |   Request Evidence|                        |                  |
  |<------------------|                        |                  |
  | Key Attestation   |                        |                  |
  | as Evidence       |                        |                  |
  |------------------------------------------->|                  |
  |  Exported Authenticator                    |                  |
  |  (Authenticator with Evidence)             |                  |
  |                   |                        |----------------->|
  |                   |                        | Send Evidence    |
  |                   |                        |<-----------------|
  |                   |                        | Attestation      |
  |                   |                        | Result           |
  |                   |                        |                  |
~~~
{: #fig-background title="Background Check Model with Client as Attester"}

# Security Considerations

This document inherits the security considerations of RFC 9261 and RFC 9334. The integrity of the exported authenticators must be guaranteed, and any failure in validating attestation evidence SHOULD be treated as a fatal error in the communication channel.

# IANA Considerations

TBD: IANA registration for registering new certificate formats.
 
--- back

# Acknowledgements

Add your name here.
