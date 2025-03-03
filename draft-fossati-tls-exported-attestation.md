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
# area: AREA
# workgroup: WG Working Group
keyword:
 - Attestation
 - TLS
 - Key Attestation
 - Exported Authenticators
venue:
  group: tls
  type: Working Group
  mail: tls@ietf.org
  arch: https://datatracker.ietf.org/wg/tls/about/
  github: "hannestschofenig/exported-attestation"
  latest: "https://hannestschofenig.github.io/exported-attestation/draft-fossati-tls-exported-attestation.html"

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
  I-D.ietf-rats-msg-wrap:

informative:
  I-D.ietf-lamps-csr-attestation:
  I-D.ietf-lamps-attestation-freshness:

--- abstract

This specification defines a method for two parties in a communication interaction to exchange Evidence and Attestation Results using exported authenticators, as defined in RFC 9261. This approach falls into the category of post-handshake attestation by exchanging payloads in the application layer protocol while binding the remote attestation to the underlying communication channel. This document supports both the passport and background check models from the RATS architecture.

--- middle

# Introduction

There is a growing need to demonstrate to a remote party that cryptographic keys are stored in a secure element, the device is in a known good state, secure boot has been enabled, and that low-level software and firmware have not been tampered with. Remote attestation provides this capability.

More technically, an Attester produces a signed collection of Claims that constitute Evidence about its running environment(s). A Relying Party may consult an Attestation Result produced by a Verifier that has appraised the Evidence to make policy decisions regarding the trustworthiness of the Target Environment being assessed. This is, in essence, what RFC 9334 {{RFC9334}} defines.

At the time of writing, several standard and proprietary remote attestation technologies are in use. This specification aims to remain as technology-agnostic as possible concerning implemented remote attestation technologies. As a result, this document focuses on the conveyance of Evidence and Attestation Results as part of the payloads defined by Exported Authenticators. The end-entity certificate is associated with key material that serves as an Attestation Key, which acts as Evidence originating from the Attester.

This document builds upon three foundational specifications:

- RATS (Remote Attestation Procedures) Architecture {{RFC9334}}: RFC 9334 defines how remote attestation systems establish trust between parties by exchanging Evidence and Attestation Results. These interactions can follow different models, such as the passport or the background check model, depending on the order of data flow in the system.

- TLS Exported Authenticators {{RFC9261}}: RFC 9261 offers bi-directional, post-handshake authentication. Once a TLS connection is established, both peers can send an authenticator request message at any point after the handshake. This message from the server and the client uses the CertificateRequest and the ClientCertificateRequest messages, respectively. The peer receiving the authenticator request message can respond with an Authenticator consisting of Certificate, CertificateVerify, and Finished messages. These messages can then be validated by the other peer.

- RATS Conceptual Messages Wrapper (CMW) {{I-D.ietf-rats-msg-wrap}}: CMW provides a convenient encapsulation of Evidence and Attestation Result payloads thereby provide an abstraction of the utilized attestation technology. This specification reuses exported authenticators to carry Evidence and/or Attestation Results wrapped via the CMW. While exported authenticators traditionally deal with certificates, in this document, we use them for key attestation. Consequently, this mechanism applies specifically to remote attestation technologies that offer key attestation, though the encoding format is not restricted to X.509 certificates.

# Terminology

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, NOT RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals as shown here.

The reader is assumed to be familiar with the vocabulary and concepts defined in RFC 9334 and RFC 9261.

We use the term REMOTE_ATTESTATION payload to refer to the opaque token generated by the TLS Exported Authenticator implementation. The content is opaque to the application layer protocol but, of course, not to the TLS Exported Authenticator implementation.

# Architecture

Designers of application layer protocols need to define payload formats for conveying exported authenticators that contain remote Evidence. They must also provide mechanisms to inform both communication partners of their ability to exchange Evidence and Attestation Results via this specification. This capability can be specified in a profile of this document or dynamically negotiated during protocol exchanges. A future version of this specification will provide more details.

The Exported Authenticator API defined in RFC 9261 accepts a request, a set of certificates, and supporting information as input. The output is an opaque token that serves as the REMOTE_ATTESTATION payload. Upon receipt of a REMOTE_ATTESTATION payload, an endpoint that supports "secondary certificates" MUST take the following steps to validate the contained token:

- Use the get context API to retrieve the certificate_request_context that was used to generate the authenticator (if any). Since the certificate_request_context for spontaneous server certificates is chosen by the server, its usage is implementation-dependent (see {{Section 5 of RFC9261}} for more details).

- Use the validate API to confirm the authenticator's validity with respect to the generated request (if any). If validation fails, this SHOULD be treated as a connection error. Upon successful validation, the endpoint can conduct further checks to ensure the certificate's acceptability.

In the following examples, the server possesses an identity certificate, while the client is not authenticated during the initial TLS exchange.

{{fig-passport}} shows the passport model while {{fig-background}} illustrates the background-check model.
For a specific instantiation of this passport model see the integration of the attested CSR {{I-D.ietf-lamps-csr-attestation}} into the CMP protocol {{I-D.ietf-lamps-attestation-freshness}}.

~~~aasvg
Client                   Server                  CA/Verifier
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
  |      Certificate Management Protocol (+CSR)      |
  |       (Evidence requested)                       |
  |<------------------------------------------------>|
  |                        |                         |
  |      Certificate (with Attestation Result)       |
  |<-------------------------------------------------|
  |                        |                         |
  | Exported Authenticator |                         |
  |  (Authenticator with   |                         |
  |   Attestation Result)  |                         |
  |----------------------->|                         |
  |                        |                         |
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
  | Authenticator Request (ClientCertReq), Nonce                  |
  |<-------------------------------------------|                  |
  |                   |                        |                  |
  | Request Evidence  |                        |                  |
  |------------------>|                        |                  |
  | Key Attestation   |                        |                  |
  | as Evidence       |                        |                  |
  |<------------------|                        |                  |
  |  Exported Authenticator                    |                  |
  |  (Authenticator with Evidence)             |                  |
  |------------------------------------------->|                  |
  |                   |                        | Send Evidence    |
  |                   |                        |----------------->|
  |                   |                        | Attestation      |
  |                   |                        | Result           |
  |                   |                        |<-----------------|
  |                   |                        |                  |
~~~
{: #fig-background title="Background Check Model with a Separate Client-Side Attester"}

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

The evidence presented in this protocol is valid only at the time it is generated and presented. To ensure that
the attested peer remains in a secure state, remote attestation must be re-initiated
periodically. With the current protocol, this requires a new post-handshake authentication protocol run to be started.

# IANA Considerations

TBD: Request a new entry in the "TLS Certificate Types" to carry a CMW.

--- back

# Acknowledgements
We would like to thank Chris Patton for his proposal to explore RFC 9261 for attested TLS.
We would also like to thank Paul Howard and Yogesh Deshpande for their input.
