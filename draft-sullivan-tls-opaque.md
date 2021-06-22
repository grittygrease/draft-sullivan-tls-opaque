---
title: OPAQUE with TLS 1.3
abbrev: TLS 1.3 OPAQUE
docname: draft-sullivan-tls-opaque-latest
category: std

ipr: trust200902
area: Security
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
       ins: N. Sullivan
       name: Nick Sullivan
       organization: Cloudflare
       email: nick@cloudflare.com
 -
       ins: H. Krawczyk
       name: Hugo Krawczyk
       organization: IBM Research
       email: hugo@ee.technion.ac.il
 -
       ins: O. Friel
       name: Owen Friel
       organization: Cisco
       email: ofriel@cisco.com
 -
       ins: R. Barnes
       name: Richard Barnes
       organization: Cisco
       email: rlb@ipv.sx

normative:
  RFC2119:
  RFC8174:
  RFC7250:

informative:
  RFC2945:
  RFC5869:
  I-D.barnes-tls-pake:
  ECH:
  I-D.irtf-cfrg-spake2:
  I-D.irtf-cfrg-opaque:
  opaque-paper:
    title: "OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks"
    date: 2018
    author:
      ins: S. Jarecki
      name: Stanislaw Jarecki
    author:
      ins: H. Krawczyk
      name: Hugo Krawczyk
    author:
      ins: J. Xu
      name: Jiayu Xu


--- abstract

This document describes two mechanisms for enabling the use of the OPAQUE
password-authenticated key exchange in TLS 1.3.

--- middle

# Introduction

Note that this draft has not received significant security review and should not be
the basis for production systems.

OPAQUE {{opaque-paper}} is a mutual authentication method that enables the establishment
of an authenticated cryptographic key between a client and server based on a user's
password, without ever exposing the password to servers or other entities other
than the client machine, and without relying on Public Key Infrastructure (PKI). OPAQUE
leverages a primitive called a Strong symmetric Password Authenticated Key Exchange (Strong aPAKE) to provide desirable
properties including resistance to pre-computation attacks in the event of a server compromise.

In some cases, it is desirable to combine password-based authentication with traditional
PKI-based authentication as a defense-in-depth measure. For example, in the case of IoT
devices, it may be useful to validate that both parties were issued a certificate from a
certain manufacturer. Another desirable property for password-based authentication systems
is the ability to hide the client’s identity from the network. This document describes the
use of OPAQUE in TLS 1.3 {{!TLS13=RFC8446}} both as part of the TLS handshake and
post-handshake facilitated by Exported Authenticators {{!I-D.ietf-tls-exported-authenticator}},
how the different approaches satisfy the above properties and the trade-offs associated with
each design.

The in-handshake instantiations of OPAQUE can be used to authenticate a TLS handshake with
a password alone, or in conjunction with certificate-based (mutual) authentication but does
not provide identity hiding for the client. The Exported Authenticators instantiation of
OPAQUE provides client identity hiding by default and allows the application to do password
authentication at any time during the connection, but requires PKI authentication for the
initial handshake and application-layer semantics to be defined for transporting
authentication messages.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.

# OPAQUE

OPAQUE {{opaque-paper}} is a Strong Asymmetric Password-Authenticated Key Exchange (Strong aPAKE) built
on an oblivious pseudo-random function (OPRF), and authenticated key exchange protocol that is secure
against key compromise impersonation (KCI) attacks and provides forward secrecy. Unlike previous PAKE methods such as SRP {{?RFC2945}}
and SPAKE-2 {{?I-D.irtf-cfrg-spake2}}, which require a public salt value, a Strong aPAKE leverages the
OPRF private key as salt, making it resistant to pre-computation attacks on the password database stored on the server.

TLS 1.3 provides a KCI-secure key agreement algorithm suitable for usage with OPAQUE. This document describes two
instantiations of OPAQUE in TLS 1.3: one based on digital signatures, called OPAQUE-Sign, and one on Diffie-Hellman
key agreement, called OPAQUE-KEX.

OPAQUE consists of two distinct phases: password registration and authentication. We will describe the
mechanisms for password registration in this document but it is assumed that it is done outside of a
TLS connection. During password registration, the client and server establish a shared set of parameters
for future authentication and two private-public key pairs are generated, one for the client and one for
the server. The server keeps its private key and stores an encapsulated copy of the client’s private key
along with its own public key in an “envelope” that is encrypted with the result of the OPRF operation.
Note that it is possible for the server to use the same private key for multiple clients. It may be necessary to
permit multiple simultaneous server keys in the even of a key rollover. The client does not store any
state nor any PKI information.

In OPAQUE-Sign, the key pairs generated at password registration time are digital signature keys. These
signature keys are used in place of certificate keys for both server and client authentication in a TLS
handshake. Client authentication is technically optional, though in practice is almost universally required.
OPAQUE-Sign cannot be used alongside certificate-based handshake authentication. This instantiation can
also be leveraged to do part of a post-handshake authentication using Exported Authenticators
{{!I-D.ietf-tls-exported-authenticator}} given an established TLS connection protected with certificate-based
authentication.

In OPAQUE-KEX, the key pairs are Diffie-Hellman keys and are used to establish a shared secret that is
fed into the key schedule for the handshake. The handshake continues to use Certificate-based authentication
and establishes the shared key using Diffie-Hellman. This instantiations is best
suited to use cases in which both password and certificate-based authentication are needed during the
initial handshake, which is useful in some scenarios. There is no unilateral authentication in this
context, mutual authentication is demonstrated explicitly through the finished messages.

# Password Registration

Password registration is run between a client and a server. It is assumed that the client can
authenticate the server during this registration phase (this is the only part in OPAQUE that
requires some form of authenticated channel, either physical, out-of-band, PKI-based, etc.)
During this phase, clients run the registration flow in {{?I-D.irtf-cfrg-opaque}} using
a specific OPAQUE configuration consisting of a tuple (OPRF, Hash, MHF, AKE). The specific
AKE is not used during the offline registration phase. It is only used during the
online authenticated key exchange phase.

During this phase, a specific OPAQUE configuration is chosen, which consists of a tuple
(OPRF, Hash, MHF, AKE). See {{?I-D.irtf-cfrg-opaque}} for details about configuration parameters.
In this context, AKE is either OPAQUE-Sign or OPAQUE-KEX.

# Password Authentication

Password authentication integrates TLS 1.3 into OPAQUE in such a way that clients prove knowledge
of a password to servers. In this section, we describe TLS extensions that support this integration
for both OPAQUE-KEX and OPAQUE-Sign.

## TLS Extensions

We define several TLS extensions to signal support for OPAQUE and transport the parameters.
The extensions used here have a similar structure to those described in Usage of PAKE with
TLS 1.3 {{?I-D.barnes-tls-pake}}. The permitted messages that these extensions are allowed and
the expected protocol flows are described below.

First, this document specifies extensions used to convey OPAQUE client and server messages,
called "opaque_client_auth" and "opaque_server_auth" respectively.

~~~~~~~~~~
  enum {
    ...
    opaque_client_auth(TBD),
    opaque_server_auth(TBD),
    (65535)
  } ExtensionType;
~~~~~~~~~~

The "opaque_client_auth" extension contains a `PAKEClientAuthExtension` struct and can only be
included in the `Certificate` message.

~~~
  struct {
    select (Handshake.msg_type) {
      Certificate:
        opaque idU<0..2^16-1>;
    }
  } PAKEClientAuthExtension;
~~~

The "opaque_server_auth" extension contains a `PAKEServerAuthExtension` struct and can only be
included in the `ClientHello`, `EncryptedExtensions`, `CertificateRequest` and `Certificate` messages,
depending on the type.

~~~~~~~~~~
  struct {
    opaque client_identity<0..2^16-1>;
    KE1 ke1;
  } PAKEShareClient;

  struct {
    opaque server_identity<0..2^16-1>;
    uint8 server_public_key[Npk];
    KE2 ke2;
  } PAKEShareServer;

  struct {
    select (Handshake.msg_type) {
      ClientHello:
        PAKEShareClient client_shares<0..2^16-1>;
        OPAQUEType types<0..2^16-1>;
      EncryptedExtensions, Certificate, CertificateRequest:
        PAKEShareServer server_share;
        OPAQUEType type;
    }
  } PAKEServerAuthExtension;
~~~~~~~~~~

This document also defines the following set of types;

~~~~~~~~~~
  enum {
    OPAQUE-Sign(1),
    OPAQUE-KEX(2),
  } OPAQUEType;
~~~~~~~~~~

Servers use PAKEShareClient.client_identity to index the user’s record on the server and create
the PAKEShareServer.ke2. The types field indicates the set of supported auth
types by the client. PAKEShareClient.ke1 and PAKEShareServer.ke2, of type
KE1 and KE2, respectively, are defined in {{?I-D.irtf-cfrg-opaque}}.

This document also describes a new CertificateEntry structure that corresponds to an authentication
via a signature derived using OPAQUE. This structure serves as a placeholder for the
PAKEServerAuthExtension extension.

~~~~~~~~~~
  struct {
    select (certificate_type) {
      case OPAQUESign:
        /* Defined in this document */
        opaque null<0>

      case RawPublicKey:
        /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
        opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;

      case X509:
        opaque cert_data<1..2^24-1>;
    };
    Extension extensions<0..2^16-1>;
  } CertificateEntry;
~~~~~~~~~~

We request that IANA add an additional type to the “TLS Certificate Types” registry for this OPAQUESign.

Support for the OPAQUESign Certificate type for server authentication can be negotiated using the
server_certificate_type {{!RFC7250}} and the Certificate type for client authentication can be
negotiated using the client_certificate_type extension {{!RFC7250}}.

Note that there needs to be a change to the client_certificate_type row in the IANA "TLS ExtensionType Values"
table to allow client_certificate_type extension to be used as an extension to the CertificateRequest message.

# Use of extensions in TLS handshake flows

## OPAQUE-KEX

In this mode, OPAQUE private keys are used for key agreement algorithm and the result is fed into the TLS key
schedule. Password validation is confirmed by the validation of the finished message. These modes can be used
in conjunction with optional Certificate-based authentication.

It should be noted that the identity of the client is not encrypted, as it is sent as an extension to
the ClientHello. This may present a privacy problem unless a mechanism like Encrypted Client Hello
{{?ECH=I-D.ietf-tls-esni}} is used to protect it.

Upon receiving a PAKEServerAuthExtension, the server checks to see if it has a matching record for this identity.
If the record does not exist, the handshake is aborted with a "illegal_parameter" alert. If the record does exist, but
the key type of the record (record.client_public_key) does not match any of the supported_groups sent in the key_share
extension of the ClientHello, a HelloRetryRequest message is sent containing the set of valid key types that it found records for.

Given a matching key_share and an identity with a matching supported_group, the server returns its PAKEServerAuth
as an extension to its EncryptedExtensions.

Both parties, then, derive a shared OPAQUE key as follows:

~~~~~~~~~~~
 Client computes:
   preamble = Preamble(client_identity, state.ke1, server_identity, ke2.inner_ke2)
   ikm = state.client_secret * ke2.server_keyshare || state.client_secret * server_pub_key || record.client_private_key * ke2.server_keyshare
   prk = Extract("", ikm)
   handshake_secret = Derive-Secret(prk, "HandshakeSecret", Hash(preamble))

 Server computes:
   preamble = Preamble(client_identity, ke1, server_identity, inner_ke2)
   ikm = server_secret * ke1.client_keyshare || server_private_key * ke1.client_keyshare || server_secret * client_public_key
   prk = Extract("", ikm)
   handshake_secret = Derive-Secret(prk, "HandshakeSecret", Hash(preamble))
~~~~~~~~~~~

Hash() is the HKDF function agreed upon in the TLS handshake. It means to apply
the cryptographic hash function to input, producing a fixed-length digest of size Nh bytes.

The result, `handshake_secret`, is then added as an input to the Master Secret
in place of the 0 value defined in TLS 1.3. Specifically,

~~~~~~~~~~~
  0 -> HKDF-Extract = Master Secret
~~~~~~~~~~~

becomes

~~~~~~~~~~~
  K -> HKDF-Extract = Master Secret
~~~~~~~~~~~

In this construction, the finished messages cannot be validated unless the OPAQUE
computation was done correctly on both sides, authenticating both client and server.

## OPAQUE-Sign

In this modes of operation, the OPAQUE private keys are used for digital signatures and are used to define a
new Certificate type and CertificateVerify algorithm. Like the OPAQUE-KEX instantiations above, the identity
of the client is sent in the clear in the client’s first flight unless a mechanism like Encrypted Client Hello
{{?ECH}} is created to protect it.

Upon receiving a PAKEServerAuth extension, the server checks to see if it has a matching record for this identity.
If the record does not exist, the handshake is aborted with a TBD error message. If the record does exist, but
the key type of the record does not match any of the supported_signatures sent in the the ClientHello, the
handshake must be aborted with a "illegal_parameter" error.

We define a new Certificate message type for an OPAQUE-Sign authenticated handshake.

~~~~~~~~~~
enum {
  X509(0),
  RawPublicKey(2),
  OPAQUE-Sign(3),
  (255)
} CertificateType;
~~~~~~~~~~

Certificates of this type have CertificateEntry structs of the form:

~~~~~~~~~~
struct {
  Extension extensions<0..2^16-1>;
} CertificateEntry;
~~~~~~~~~~

Given a matching signature_scheme and an identity with a matching key type, the server returns a certificate message
with type OPAQUE-Sign with PAKEServerAuthExtension as an extension. The private key used in the CertificateVerify message
is set to the private key used during account registration, and the client verifies it using the server public key
contained in the client's envelope.

It is RECOMMENDED that the server includes a CertificateRequest message with a PAKEClientAuthExtension and the identity originally
received in the PAKEServerAuthExtension from the client hello. On receiving a CertificateRequest message with a PAKEClientAuthExtension, the client returns a CertificateVerify message signed by the client's private key used during account registration which is validated by the server using the corresponding public key from the client.

# Integration into Exported Authenticators

Neither of the above mechanisms provides privacy for the user during the authentication phase, as the user id is sent in
the clear. Additionally, OPAQUE-Sign has the drawback that it cannot be used in conjunction with certificate-based authentication.

It is possible to address both the privacy concerns and the requirement for certificate-based authentication by using OPAQUE-Sign
in an Exported Authenticator {{!I-D.ietf-tls-exported-authenticator}} flow, since exported authenticators are sent over a secure
channel that is typically established with certificate-based authentication. Using Exported Authenticators for OPAQUE has the
additional benefit that it can be triggered at any time after a TLS session has been established, which better fits modern
web-based authentication mechanism.

The ClientHello contains PAKEServerAuthExtension, PAKEClientAuthExtension with empty identity values to indicate support for these mechanisms.

1. Client creates Authenticator Request with CertificateRequest PAKEServerAuthExtension.
2. Server creates Exported Authenticator with OPAQUE-Sign (PAKEServerAuthExtension) and CertificateVerify (signed with the OPAQUE private key).

If the server would like to then establish mutual authentication, it can do the following:

1. Server creates Authenticator Request with ClientHello PAKEClientAuthExtension (identity)
2. Client creates Exported Authenticator with OPAQUE-Sign Certificate and CertificateVerify (signed with user private key derived
  from the envelope).

Support for Exported Authenticators is negotiated at the application layer.

# Summary of properties

 Variant \ Property | Identity hiding | Certificate auth | Server-only auth | Post-handshake auth | Minimum round trips
    OPAQUE-Sign with EA | yes | yes | yes | yes | 2-RTT
    OPAQUE-Sign | no | no | yes | no | 1-RTT
    OPAQUE-KEX | no | no | no | no | 1-RTT

# Privacy considerations

TBD: cleartext identity, etc

# Security Considerations

TODO: protecting against user enumeration

# IANA Considerations

* Existing IANA references have not been updated yet to point to this document.

   IANA is asked to register a new value in the "TLS Certificate Types"
   registry of Transport Layer Security (TLS) Extensions (TLS-
   Certificate-Types-Registry), as follows:

* Value: 4 Description: OPAQUE Authentication Reference: This RFC

Correction request: The client_certificate_type row in the IANA TLS ExtensionType Values table to allow client_certificate_type extension to be used as an extension to the CertificateRequest message.

--- back

# Acknowledgments

