#pragma once

typedef __int8 int8;
typedef __int16 int16;
typedef __int32 int32;
typedef unsigned __int8 uint8;
typedef unsigned __int16 uint16;
typedef unsigned __int32 uint32;
typedef __int64 int64;
typedef unsigned __int64 uint64;
typedef uint32 uintn;

typedef struct {
  uint32  Data1;
  uint16  Data2;
  uint16  Data3;
  uint8   Data4[8];
} EFI_GUID;

#define EFI_GLOBAL_VARIABLE_GUID \
    {0x8BE4DF61, 0x93CA, 0x11d2, {0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C} }

#define EFI_LOADED_IMAGE_PROTOCOL_GUID\
	{0x5B1B31A1, 0x9562, 0x11d2, {0x8E,0x3F,0x00,0xA0,0xC9,0x69,0x72,0x3B}}

#define EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID \
	{0x0964e5b22, 0x6459, 0x11d2, {0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}}

//
// EFI Time Abstraction:
//  Year:       2000 - 20XX
//  Month:      1 - 12
//  Day:        1 - 31
//  Hour:       0 - 23
//  Minute:     0 - 59
//  Second:     0 - 59
//  Nanosecond: 0 - 999,999,999
//  TimeZone:   -1440 to 1440 or 2047
//
typedef struct {
  uint16  Year;
  uint8   Month;
  uint8   Day;
  uint8   Hour;
  uint8   Minute;
  uint8   Second;
  uint8   Pad1;
  uint32  Nanosecond;
  int16   TimeZone;
  uint8   Daylight;
  uint8   Pad2;
} EFI_TIME;

//***********************************************************************
// Signature Database
//***********************************************************************
///
/// The format of a signature database. 
///

typedef uint8  EFI_SHA256_HASH[32];
typedef uint8  EFI_SHA384_HASH[48];
typedef uint8  EFI_SHA512_HASH[64];

///
/// The WIN_CERTIFICATE structure is part of the PE/COFF specification.
///
typedef struct {
  ///
  /// The length of the entire certificate,  
  /// including the length of the header, in uint8s.                                
  ///
  uint32  dwLength;
  ///
  /// The revision level of the WIN_CERTIFICATE 
  /// structure. The current revision level is 0x0200.                                   
  ///
  uint16  wRevision;
  ///
  /// The certificate type. See WIN_CERT_TYPE_xxx for the UEFI      
  /// certificate types. The UEFI specification reserves the range of 
  /// certificate type values from 0x0EF0 to 0x0EFF.                          
  ///
  uint16  wCertificateType;
  ///
  /// The following is the actual certificate. The format of   
  /// the certificate depends on wCertificateType.
  ///
  /// uint8 bCertificate[ANYSIZE_ARRAY];
  ///
} WIN_CERTIFICATE;

#pragma pack(1)

typedef struct {
  ///
  /// An identifier which identifies the agent which added the signature to the list.
  ///
  EFI_GUID          SignatureOwner;
  ///
  /// The format of the signature is defined by the SignatureType.
  ///
  uint8             SignatureData[1];
} EFI_SIGNATURE_DATA;

typedef struct {
  ///
  /// Type of the signature. GUID signature types are defined in below.
  ///
  EFI_GUID            SignatureType;
  ///
  /// Total size of the signature list, including this header.
  ///
  uint32              SignatureListSize;
  ///
  /// Size of the signature header which precedes the array of signatures.
  ///
  uint32              SignatureHeaderSize;
  ///
  /// Size of each signature.
  ///
  uint32              SignatureSize; 
  ///
  /// Header before the array of signatures. The format of this header is specified 
  /// by the SignatureType.
  /// uint8           SignatureHeader[SignatureHeaderSize];
  ///
  /// An array of signatures. Each signature is SignatureSize uint8s in length. 
  /// EFI_SIGNATURE_DATA Signatures[][SignatureSize];
  ///
} EFI_SIGNATURE_LIST;

typedef struct {
  ///
  /// The SHA256 hash of an X.509 certificate's To-Be-Signed contents.
  ///
  EFI_SHA256_HASH     ToBeSignedHash;
  ///
  /// The time that the certificate shall be considered to be revoked.
  ///
  EFI_TIME            TimeOfRevocation;
} EFI_CERT_X509_SHA256;

typedef struct {
  ///
  /// The SHA384 hash of an X.509 certificate's To-Be-Signed contents.
  ///
  EFI_SHA384_HASH     ToBeSignedHash;
  ///
  /// The time that the certificate shall be considered to be revoked.
  ///
  EFI_TIME            TimeOfRevocation;
} EFI_CERT_X509_SHA384;

typedef struct {
  ///
  /// The SHA512 hash of an X.509 certificate's To-Be-Signed contents.
  ///
  EFI_SHA512_HASH     ToBeSignedHash;
  ///
  /// The time that the certificate shall be considered to be revoked.
  ///
  EFI_TIME            TimeOfRevocation;
} EFI_CERT_X509_SHA512;

#pragma pack()

//
// _WIN_CERTIFICATE.wCertificateType
// 
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA 0x0002
#define WIN_CERT_TYPE_EFI_PKCS115      0x0EF0
#define WIN_CERT_TYPE_EFI_GUID         0x0EF1

#define EFI_CERT_X509_GUID \
  (EFI_GUID){								\
    0xa5c059a1, 0x94e4, 0x4aa7, {0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72} \
  }

#define EFI_CERT_RSA2048_GUID \
  (EFI_GUID){								\
    0x3c5766e8, 0x269c, 0x4e34, {0xaa, 0x14, 0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6} \
  }


#define EFI_CERT_TYPE_PKCS7_GUID \
  (EFI_GUID){								\
    0x4aafd29d, 0x68df, 0x49ee, {0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7} \
  }

#define EFI_CERT_X509_SHA256_GUID \
	(EFI_GUID) { 0x3bd2a492, 0x96c0, 0x4079,		\
			{ 0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed } }

#define EFI_CERT_X509_SHA384_GUID \
	(EFI_GUID) { 0x7076876e, 0x80c2, 0x4ee6,		\
			{ 0xaa, 0xd2, 0x28, 0xb3, 0x49, 0xa6, 0x86, 0x5b } }

#define EFI_CERT_X509_SHA512_GUID \
	(EFI_GUID) { 0x446dbf63, 0x2502, 0x4cda,		\
			{ 0xbc, 0xfa, 0x24, 0x65, 0xd2, 0xb0, 0xfe, 0x9d } }

///
/// WIN_CERTIFICATE_UEFI_GUID.CertType
/// 
#define EFI_CERT_TYPE_RSA2048_SHA256_GUID \
  {0xa7717414, 0xc616, 0x4977, {0x94, 0x20, 0x84, 0x47, 0x12, 0xa7, 0x35, 0xbf } }

///
/// WIN_CERTIFICATE_UEFI_GUID.CertData
/// 
typedef struct {
  EFI_GUID  HashType;
  uint8     PublicKey[256];
  uint8     Signature[256];
} EFI_CERT_BLOCK_RSA_2048_SHA256;


///
/// Certificate which encapsulates a GUID-specific digital signature
///
typedef struct {
  ///
  /// This is the standard WIN_CERTIFICATE header, where
  /// wCertificateType is set to WIN_CERT_TYPE_UEFI_GUID. 
  ///                         
  WIN_CERTIFICATE   Hdr;
  ///
  /// This is the unique id which determines the 
  /// format of the CertData. .
  ///
  EFI_GUID          CertType;
  /// 
  /// The following is the certificate data. The format of
  /// the data is determined by the CertType. 
  /// If CertType is EFI_CERT_TYPE_RSA2048_SHA256_GUID,
  /// the CertData will be EFI_CERT_BLOCK_RSA_2048_SHA256 structure.
  ///
  uint8            CertData[1];
} WIN_CERTIFICATE_UEFI_GUID;


///   
/// Certificate which encapsulates the RSASSA_PKCS1-v1_5 digital signature.
///  
/// The WIN_CERTIFICATE_UEFI_PKCS1_15 structure is derived from
/// WIN_CERTIFICATE and encapsulate the information needed to  
/// implement the RSASSA-PKCS1-v1_5 digital signature algorithm as  
/// specified in RFC2437.  
///  
typedef struct {     
  ///
  /// This is the standard WIN_CERTIFICATE header, where 
  /// wCertificateType is set to WIN_CERT_TYPE_UEFI_PKCS1_15.                       
  ///
  WIN_CERTIFICATE Hdr;
  ///
  /// This is the hashing algorithm which was performed on the
  /// UEFI executable when creating the digital signature. 
  ///
  EFI_GUID        HashAlgorithm;
  ///
  /// The following is the actual digital signature. The   
  /// size of the signature is the same size as the key 
  /// (1024-bit key is 128 uint8s) and can be determined by 
  /// subtracting the length of the other parts of this header
  /// from the total length of the certificate as found in 
  /// Hdr.dwLength.                               
  ///
  /// uint8 Signature[];
  ///
} WIN_CERTIFICATE_EFI_PKCS1_15;

#define OFFSET_OF(TYPE, Field) ((UINTN) &(((TYPE *)0)->Field))

///
/// Attributes of Authenticated Variable
///
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS              0x00000010
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS   0x00000020
#define EFI_VARIABLE_APPEND_WRITE                            0x00000040

///   
/// AuthInfo is a WIN_CERTIFICATE using the wCertificateType
/// WIN_CERTIFICATE_UEFI_GUID and the CertType
/// EFI_CERT_TYPE_RSA2048_SHA256_GUID. If the attribute specifies
/// authenticated access, then the Data buffer should begin with an
/// authentication descriptor prior to the data payload and DataSize
/// should reflect the the data.and descriptor size. The caller
/// shall digest the Monotonic Count value and the associated data
/// for the variable update using the SHA-256 1-way hash algorithm.
/// The ensuing the 32-uint8 digest will be signed using the private
/// key associated w/ the public/private 2048-bit RSA key-pair. The
/// WIN_CERTIFICATE shall be used to describe the signature of the
/// Variable data *Data. In addition, the signature will also
/// include the MonotonicCount value to guard against replay attacks.
///  
typedef struct {
  ///
  /// Included in the signature of        
  /// AuthInfo.Used to ensure freshness/no
  /// replay. Incremented during each     
  /// "Write" access.   
  ///                  
  uint64                      MonotonicCount;
  ///
  /// Provides the authorization for the variable 
  /// access. It is a signature across the        
  /// variable data and the  Monotonic Count      
  /// value. Caller uses Private key that is      
  /// associated with a public key that has been  
  /// provisioned via the key exchange.           
  ///
  WIN_CERTIFICATE_UEFI_GUID   AuthInfo;
} EFI_VARIABLE_AUTHENTICATION;

///
/// When the attribute EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS is 
/// set, then the Data buffer shall begin with an instance of a complete (and serialized)
/// EFI_VARIABLE_AUTHENTICATION_2 descriptor. The descriptor shall be followed by the new 
/// variable value and DataSize shall reflect the combined size of the descriptor and the new 
/// variable value. The authentication descriptor is not part of the variable data and is not 
/// returned by subsequent calls to GetVariable().
///
typedef struct {
  ///
  /// For the TimeStamp value, components Pad1, Nanosecond, TimeZone, Daylight and 
  /// Pad2 shall be set to 0. This means that the time shall always be expressed in GMT.
  ///
  EFI_TIME                    TimeStamp;
  /// 
  /// Only a CertType of  EFI_CERT_TYPE_PKCS7_GUID is accepted.
  ///
  WIN_CERTIFICATE_UEFI_GUID   AuthInfo;
 } EFI_VARIABLE_AUTHENTICATION_2;

///
/// Size of AuthInfo prior to the data payload.
///
#define AUTHINFO_SIZE ((OFFSET_OF (EFI_VARIABLE_AUTHENTICATION, AuthInfo)) + \
                       (OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData)) + \
                       sizeof (EFI_CERT_BLOCK_RSA_2048_SHA256))

#define AUTHINFO2_SIZE(VarAuth2) ((OFFSET_OF (EFI_VARIABLE_AUTHENTICATION_2, AuthInfo)) + \
                                  (UINTN) ((EFI_VARIABLE_AUTHENTICATION_2 *) (VarAuth2))->AuthInfo.Hdr.dwLength)

#define OFFSET_OF_AUTHINFO2_CERT_DATA ((OFFSET_OF (EFI_VARIABLE_AUTHENTICATION_2, AuthInfo)) + \
(OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData)))

