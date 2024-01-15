// (c) 2023-present, LDC Labs. All rights reserved.
// See the file LICENSE for licensing terms.

// IANA-registered COSE common key parameters.
//
// From IANA registry <https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters>
// as of 2022-12-19.

// Reserved value.
export const KeyParameterReserved = 0
// Identification of the key type
//
// Associated value of type tstr / int
export const KeyParameterKty = 1
// Key identification value - match to kid in message
//
// Associated value of type bstr
export const KeyParameterKid = 2
// Key usage restriction to this algorithm
//
// Associated value of type tstr / int
export const KeyParameterAlg = 3
// Restrict set of permissible operations
//
// Associated value of type [+ (tstr / int)]
export const KeyParameterKeyOps = 4
// Base IV to be XORed with Partial IVs
//
// Associated value of type bstr
export const KeyParameterBaseIV = 5

// IANA-registered COSE key types.
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#key-type
// as of 2022-12-19.

// This value is reserved
export const KeyTypeReserved = 0
// Octet Key Pair
export const KeyTypeOKP = 1
// Elliptic Curve Keys w/ x- and y-coordinate pair
export const KeyTypeEC2 = 2
// RSA Key
export const KeyTypeRSA = 3
// Symmetric Keys
export const KeyTypeSymmetric = 4
// Public key for HSS/LMS hash-based digital signature
export const KeyTypeHSS_LMS = 5
// WalnutDSA public key
export const KeyTypeWalnutDSA = 6

// IANA-registered COSE key parameters for keys of type [KeyType::OKP].
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
// as of 2022-12-19.

// EC identifier - Taken from the "COSE Elliptic Curves" registry
//
// Associated value of type tstr / int
export const OKPKeyParameterCrv = -1
// x-coordinate
//
// Associated value of type bstr
export const OKPKeyParameterX = -2
// Private key
//
// Associated value of type bstr
export const OKPKeyParameterD = -4

// IANA-registered COSE key parameters for keys of type [KeyType::EC2].
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
// as of 2022-12-19.

// EC identifier - Taken from the "COSE Elliptic Curves" registry
//
// Associated value of type tstr / int
export const EC2KeyParameterCrv = -1
// Public Key
//
// Associated value of type bstr
export const EC2KeyParameterX = -2
// y-coordinate
//
// Associated value of type bstr / bool
export const EC2KeyParameterY = -3
// Private key
//
// Associated value of type bstr
export const EC2KeyParameterD = -4

// IANA-registered COSE key parameters for keys of type [KeyType::RSA].
//
// From IANA registry <https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters>
// as of 2022-12-19.

// The RSA modulus n
//
// Associated value of type bstr
export const RSAKeyParameterN = -1
// The RSA public exponent e
//
// Associated value of type bstr
export const RSAKeyParameterE = -2
// The RSA private exponent d
//
// Associated value of type bstr
export const RSAKeyParameterD = -3
// The prime factor p of n
//
// Associated value of type bstr
export const RSAKeyParameterP = -4
// The prime factor q of n
//
// Associated value of type bstr
export const RSAKeyParameterQ = -5
// dP is d mod (p - 1)
//
// Associated value of type bstr
export const RSAKeyParameterDP = -6
// dQ is d mod (q - 1)
//
// Associated value of type bstr
export const RSAKeyParameterDQ = -7
// qInv is the CRT coefficient q^(-1) mod p
//
// Associated value of type bstr
export const RSAKeyParameterQInv = -8
// Other prime infos, an array
//
// Associated value of type array
export const RSAKeyParameterOther = -9
// a prime factor r_i of n, where i >= 3
//
// Associated value of type bstr
export const RSAKeyParameterRI = -10
// d_i = d mod (r_i - 1)
//
// Associated value of type bstr
export const RSAKeyParameterDI = -11
// The CRT coefficient t_i = (r_1 * r_2 * ... * r_(i-1))^(-1) mod r_i
//
// Associated value of type bstr
export const RSAKeyParameterTI = -12

// IANA-registered COSE key parameters for keys of type [KeyType::Symmetric].
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
// as of 2022-12-19.

// Key Value
//
// Associated value of type bstr
export const SymmetricKeyParameterK = -1

// IANA-registered COSE key parameters for keys of type [KeyType::HSS_LMS].
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
// as of 2022-12-19.

// Public key for HSS/LMS hash-based digital signature
//
// Associated value of type bstr
export const HSS_LMSKeyParameterPub = -1

// IANA-registered COSE key parameters for keys of type [KeyType::WalnutDSA].
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
// as of 2022-12-19.

// Group and Matrix (NxN) size
//
// Associated value of type uint
export const WalnutDSAKeyParameterN = -1
// Finite field F_q
//
// Associated value of type uint
export const WalnutDSAKeyParameterQ = -2
// List of T-values, enties in F_q
//
// Associated value of type array of uint
export const WalnutDSAKeyParameterTValues = -3
// NxN Matrix of enties in F_q in column-major form
//
// Associated value of type array of array of uint
export const WalnutDSAKeyParameterMatrix1 = -4
// Permutation associated with matrix 1
//
// Associated value of type array of uint
export const WalnutDSAKeyParameterPermutation1 = -5
// NxN Matrix of enties in F_q in column-major form
//
// Associated value of type array of array of uint
export const WalnutDSAKeyParameterMatrix2 = -6

// IANA-registered COSE algorithms.
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#algorithms
// as of 2022-12-19.

// RSASSA-PKCS1-v1_5 using SHA-1
export const AlgorithmRS1 = -65535
// WalnutDSA signature
export const AlgorithmWalnutDSA = -260
// RSASSA-PKCS1-v1_5 using SHA-512
export const AlgorithmRS512 = -259
// RSASSA-PKCS1-v1_5 using SHA-384
export const AlgorithmRS384 = -258
// RSASSA-PKCS1-v1_5 using SHA-256
export const AlgorithmRS256 = -257
// ECDSA using secp256k1 curve and SHA-256
export const AlgorithmES256K = -47
// HSS/LMS hash-based digital signature
export const AlgorithmHSS_LMS = -46
// SHAKE-256 512-bit Hash Value
export const AlgorithmSHAKE256 = -45
// SHA-2 512-bit Hash
export const AlgorithmSHA_512 = -44
// SHA-2 384-bit Hash
export const AlgorithmSHA_384 = -43
// RSAES-OAEP w/ SHA-512
export const AlgorithmRSAES_OAEP_SHA_512 = -42
// RSAES-OAEP w/ SHA-256
export const AlgorithmRSAES_OAEP_SHA_256 = -41
// RSAES-OAEP w/ SHA-1
export const AlgorithmRSAES_OAEP_RFC_8017_default = -40
// RSASSA-PSS w/ SHA-512
export const AlgorithmPS512 = -39
// RSASSA-PSS_SHA-384
export const AlgorithmPS384 = -38
// RSASSA-PSS w/ SHA-256
export const AlgorithmPS256 = -37
// ECDSA w/ SHA-512
export const AlgorithmES512 = -36
// ECDSA w/ SHA-384
export const AlgorithmES384 = -35
// ECDH SS w/ Concat KDF and AES Key Wrap w/ 256-bit key
export const AlgorithmECDH_SS_A256KW = -34
// ECDH SS w/ Concat KDF and AES Key Wrap w/ 192-bit key
export const AlgorithmECDH_SS_A192KW = -33
// ECDH SS w/ Concat KDF and AES Key Wrap w/ 128-bit key
export const AlgorithmECDH_SS_A128KW = -32
// ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key
export const AlgorithmECDH_ES_A256KW = -31
// ECDH ES w/ Concat KDF and AES Key Wrap w/ 192-bit key
export const AlgorithmECDH_ES_A192KW = -30
// ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key
export const AlgorithmECDH_ES_A128KW = -29
// ECDH SS w/ HKDF - generate key directly
export const AlgorithmECDH_SS_HKDF_512 = -28
// ECDH SS w/ HKDF - generate key directly
export const AlgorithmECDH_SS_HKDF_256 = -27
// ECDH ES w/ HKDF - generate key directly
export const AlgorithmECDH_ES_HKDF_512 = -26
// ECDH ES w/ HKDF - generate key directly
export const AlgorithmECDH_ES_HKDF_256 = -25
// SHAKE-128 256-bit Hash Value
export const AlgorithmSHAKE128 = -18
// SHA-2 512-bit Hash truncated to 256-bits
export const AlgorithmSHA_512_256 = -17
// SHA-2 256-bit Hash
export const AlgorithmSHA_256 = -16
// SHA-2 256-bit Hash truncated to 64-bits
export const AlgorithmSHA_256_64 = -15
// SHA-1 Hash
export const AlgorithmSHA_1 = -14
// Shared secret w/ AES-MAC 256-bit key
export const AlgorithmDirect_HKDF_AES_256 = -13
// Shared secret w/ AES-MAC 128-bit key
export const AlgorithmDirect_HKDF_AES_128 = -12
// Shared secret w/ HKDF and SHA-512
export const AlgorithmDirect_HKDF_SHA_512 = -11
// Shared secret w/ HKDF and SHA-256
export const AlgorithmDirect_HKDF_SHA_256 = -10
// EdDSA
export const AlgorithmEdDSA = -8
// ECDSA w/ SHA-256
export const AlgorithmES256 = -7
// Direct use of CEK
export const AlgorithmDirect = -6
// AES Key Wrap w/ 256-bit key
export const AlgorithmA256KW = -5
// AES Key Wrap w/ 192-bit key
export const AlgorithmA192KW = -4
// AES Key Wrap w/ 128-bit key
export const AlgorithmA128KW = -3
// Reserved
export const AlgorithmReserved = 0
// AES-GCM mode w/ 128-bit key, 128-bit tag
export const AlgorithmA128GCM = 1
// AES-GCM mode w/ 192-bit key, 128-bit tag
export const AlgorithmA192GCM = 2
// AES-GCM mode w/ 256-bit key, 128-bit tag
export const AlgorithmA256GCM = 3
// HMAC w/ SHA-256 truncated to 64 bits
export const AlgorithmHMAC_256_64 = 4
// HMAC w/ SHA-256
export const AlgorithmHMAC_256_256 = 5
// HMAC w/ SHA-384
export const AlgorithmHMAC_384_384 = 6
// HMAC w/ SHA-512
export const AlgorithmHMAC_512_512 = 7
// AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce
export const AlgorithmAES_CCM_16_64_128 = 10
// AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce
export const AlgorithmAES_CCM_16_64_256 = 11
// AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce
export const AlgorithmAES_CCM_64_64_128 = 12
// AES-CCM mode 256-bit key, 64-bit tag, 7-byte nonce
export const AlgorithmAES_CCM_64_64_256 = 13
// AES-MAC 128-bit key, 64-bit tag
export const AlgorithmAES_MAC_128_64 = 14
// AES-MAC 256-bit key, 64-bit tag
export const AlgorithmAES_MAC_256_64 = 15
// ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag
export const AlgorithmChaCha20Poly1305 = 24
// AES-MAC 128-bit key, 128-bit tag
export const AlgorithmAES_MAC_128_128 = 25
// AES-MAC 256-bit key, 128-bit tag
export const AlgorithmAES_MAC_256_128 = 26
// AES-CCM mode 128-bit key, 128-bit tag, 13-byte nonce
export const AlgorithmAES_CCM_16_128_128 = 30
// AES-CCM mode 256-bit key, 128-bit tag, 13-byte nonce
export const AlgorithmAES_CCM_16_128_256 = 31
// AES-CCM mode 128-bit key, 128-bit tag, 7-byte nonce
export const AlgorithmAES_CCM_64_128_128 = 32
// AES-CCM mode 256-bit key, 128-bit tag, 7-byte nonce
export const AlgorithmAES_CCM_64_128_256 = 33
// For doing IV generation for symmetric algorithms.
export const AlgorithmIV_GENERATION = 34

// IANA-registered COSE elliptic curves.
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
// as of 2022-12-19.

export const EllipticCurveReserved = 0
// EC2: NIST P-256 also known as secp256r1
export const EllipticCurveP_256 = 1
// EC2: NIST P-384 also known as secp384r1
export const EllipticCurveP_384 = 2
// EC2: NIST P-521 also known as secp521r1
export const EllipticCurveP_521 = 3
// OKP: X25519 for use w/ ECDH only
export const EllipticCurveX25519 = 4
// OKP: X448 for use w/ ECDH only
export const EllipticCurveX448 = 5
// OKP: Ed25519 for use w/ EdDSA only
export const EllipticCurveEd25519 = 6
// OKP: Ed448 for use w/ EdDSA only
export const EllipticCurveEd448 = 7
// EC2: SECG secp256k1 curve
export const EllipticCurveSecp256k1 = 8

// IANA-registered COSE header parameters.
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
// as of 2022-12-19.

// Reserved
export const HeaderParameterReserved = 0
// Cryptographic algorithm to use
//
// Associated value of type int / tstr
//
// It is a protected header parameter https://datatracker.ietf.org/doc/html/rfc9052#name-common-cose-header-paramete
export const HeaderParameterAlg = 1
// Critical headers to be understood
//
// Associated value of type [+ label]
//
// It is a protected header parameter
export const HeaderParameterCrit = 2
// Content type of the payload
//
// Associated value of type tstr / uint
export const HeaderParameterContentType = 3
// Key identifier
//
// Associated value of type bstr
export const HeaderParameterKid = 4
// Full Initialization Vector
//
// Associated value of type bstr
export const HeaderParameterIV = 5
// Partial Initialization Vector
//
// Associated value of type bstr
export const HeaderParameterPartialIV = 6
// CBOR-encoded signature structure
//
// Associated value of type COSE_Signature / [+ COSE_Signature ]
export const HeaderParameterCounterSignature = 7
// Counter signature with implied signer and headers
//
// Associated value of type bstr
export const HeaderParameterCounterSignature0 = 9
// Identifies the context for the key identifier
//
// Associated value of type bstr
export const HeaderParameterKidContext = 10
// V2 countersignature attribute
//
// Associated value of type COSE_Countersignature / [+ COSE_Countersignature]
export const HeaderParameterCountersignatureV2 = 11
// V2 Abbreviated Countersignature
//
// Associated value of type COSE_Countersignature0
export const HeaderParameterCountersignature0V2 = 11
// An unordered bag of X.509 certificates
//
// Associated value of type COSE_X509
export const HeaderParameterX5Bag = 32
// An ordered chain of X.509 certificates
//
// Associated value of type COSE_X509
export const HeaderParameterX5Chain = 33
// Hash of an X.509 certificate
//
// Associated value of type COSE_CertHash
export const HeaderParameterX5T = 34
// URI pointing to an X.509 certificate
//
// Associated value of type uri
export const HeaderParameterX5U = 35
// Challenge Nonce
//
// Associated value of type bstr
export const HeaderParameterCuphNonce = 256
// Public Key
//
// Associated value of type array
export const HeaderParameterCuphOwnerPubKey = 257

// IANA-registered COSE header algorithm parameters.
//
// From IANA registry https://www.iana.org/assignments/cose/cose.xhtml#header-algorithm-parameters
// as of 2022-12-19.

// static key X.509 certificate chain
//
// Associated value of type COSE_X509
export const HeaderAlgorithmParameterX5ChainSender = -29
// URI for the sender's X.509 certificate
//
// Associated value of type uri
export const HeaderAlgorithmParameterX5USender = -28
// Thumbprint for the sender's X.509 certificate
//
// Associated value of type COSE_CertHash
export const HeaderAlgorithmParameterX5TSender = -27
// Party V other provided information
//
// Associated value of type bstr
export const HeaderAlgorithmParameterPartyVOther = -26
// Party V provided nonce
//
// Associated value of type bstr / int
export const HeaderAlgorithmParameterPartyVNonce = -25
// Party V identity information
//
// Associated value of type bstr
export const HeaderAlgorithmParameterPartyVIdentity = -24
// Party U other provided information
//
// Associated value of type bstr
export const HeaderAlgorithmParameterPartyUOther = -23
// Party U provided nonce
//
// Associated value of type bstr / int
export const HeaderAlgorithmParameterPartyUNonce = -22
// Party U identity information
//
// Associated value of type bstr
export const HeaderAlgorithmParameterPartyUIdentity = -21
// Random salt
//
// Associated value of type bstr
export const HeaderAlgorithmParameterSalt = -20
// Static public key identifier for the sender
//
// Associated value of type bstr
export const HeaderAlgorithmParameterStaticKeyId = -3
// Static public key for the sender
//
// Associated value of type COSE_Key
export const HeaderAlgorithmParameterStaticKey = -2
// Ephemeral public key for the sender
//
// Associated value of type COSE_Key
export const HeaderAlgorithmParameterEphemeralKey = -1

// Key operation values.
//
// See https://datatracker.ietf.org/doc/html/rfc9052#name-key-operation-values

// Key is used to create signatures. Requires private key fields.
export const KeyOperationSign = 1
// Key is used for verification of signatures.
export const KeyOperationVerify = 2
// Key is used for key transport encryption.
export const KeyOperationEncrypt = 3
// Key is used for key transport decryption. Requires private key fields.
export const KeyOperationDecrypt = 4
// Key is used for key wrap encryption.
export const KeyOperationWrapKey = 5
// Key is used for key wrap decryption.  Requires private key fields.
export const KeyOperationUnwrapKey = 6
// Key is used for deriving keys.  Requires private key fields.
export const KeyOperationDeriveKey = 7
// Key is used for deriving bits not to be used as a key.  Requires private key fields.
export const KeyOperationDeriveBits = 8
// Key is used for creating MACs.
export const KeyOperationMacCreate = 9
// Key is used for validating MACs.
export const KeyOperationMacVerify = 10

// CBOR tag values for COSE structures.
//
// From IANA registry https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml
// as of 2022-12-19.

// COSE Single Recipient Encrypted Data Object
export const CBORTagCOSEEncrypt0 = 16
// COSE Mac w/o Recipients Object
export const CBORTagCOSEMac0 = 17
// COSE Single Signer Data Object
export const CBORTagCOSESign1 = 18
// CBOR Web Token (CWT)
export const CBORTagCWT = 61
// COSE Encrypted Data Object
export const CBORTagCOSEEncrypt = 96
// COSE MACed Data Object
export const CBORTagCOSEMac = 97
// COSE Signed Data Object
export const CBORTagCOSESign = 98
