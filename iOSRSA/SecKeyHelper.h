#ifndef SECKEYHELPER_H
#define SECKEYHELPER_H

//
//  SecKeyHelper.h
//  iOSRSA
//
//  Created by William Sherif on 4/20/13.
//  Copyright (c) 2013 William Sherif. All rights reserved.
//

// THIS FILE SHOWS HOW TO ENCRYPT FROM A PUBLIC KEY LOADED FROM A CERTIFICATE FILE.

// 
//                   FACTS      
//
// 1) YOU'RE NOT SUPPOSED TO LOAD PUBLIC KEYS IN IOS FROM 
//    ANYTHING OTHER THAN A "CERTIFICATE".  NO BASE64 ENCODED
//    ----- BEGIN PUBLIC KEY ------ STRINGS ARE SUPPORTED ON IOS BY DEFAULT.
// 2) CERTIFICATES ARE EASY TO CREATE USING OpenSSL OR certutil ON WINDOWS
// The basic steps are:
//
//
//             HOW TO MAKE A CERTIFICATE
//
//
// #Make the -----RSA PRIVATE KEY----- file in PEM format
// $ openssl genrsa -out privKey.pem 2048
//
// #Make the -----CERTIFICATE REQUEST-----
// $ openssl req -new -key privKey.pem -out certReq.pem
//
// #Make the actual -----CERTIFICATE-----
// $ openssl x509 -req -days 2000 -in certReq.pem -signkey privKey.pem -out certificate.pem
//
// #Make the DER certificate.crt file from the certificate.pem
// $ openssl x509 -outform der -in certificate.pem -out certificate.cer
// SEE http://stackoverflow.com/questions/9728799/using-an-rsa-public-key-on-ios/16096064#16096064
// SEE ALSO: OpenSSL HOWTO:  http://www.openssl.org/docs/HOWTO/certificates.txt

// DO NOT FOLLOW WINGOFHERMES' METHOD FOR LOADING PUBLIC KEYS FROM BASE64 ENCODED STRINGS.
// THIS IS NOT SUPPORTED FOR A __REASON__ AND IS NOT THE RECOMMENDED CODE PATH.
// 
// YOU'VE BEEN WARNED http://blog.wingsofhermes.org/?p=75

// RELEVANT DEVFORUMS.APPLE THREADS:

// 1) USE CERTIFICATES:
// https://devforums.apple.com/message/135272#135272
// In general we recommend that you distribute key material to
// clients as either a certificate (for public keys) or a PKCS#12
// (for private keys or identities).  iPhone OS has good support
// for importing these types of data.

// 2) IF YOU HAVE THE DER DATA, YOU CAN CREATE A CERTIFICATE
// https://devforums.apple.com/message/135288#135288
// If you have a blob of data in DER form, you can create a SecCertificateRef
// from it using SecCertificateCreateWithData.  Once you have a certificate ref,
// you can extract the public key using SecTrustCopyPublicKey.
// There's one gotcha with this, as explained in the following post.
// https://devforums.apple.com/message/114555#114555

// 3) HOW TO LOAD A CERTIFICATE
// https://devforums.apple.com/message/114555#114555
// This is surprisingly easy.  You don't need to add the certificate
// to the keychain to handle this case.  Rather, just load the
// certificate data (that is, the contents of a .cer file) in 
// your application (you can either get this from your bundle 
// or off the network) and then create a certificate ref using 
// SecCertificateCreateWithData.  From there you can extract a 
// public key ref using a SecTrust object (SecTrustCreateWithCertificates, 
// SecTrustEvaluate -- you can choose to ignore the resulting 
// SecTrustResultType -- and SecTrustCopyPublicKey).  
// And from there you can encrypt and verify using the
// SecKey APIs (SecKeyEncrypt, SecKeyRawVerify).

//  The base ctor is too large.
CFMutableDictionaryRef CFMutableDictionaryCreateEmpty();

// We have to create the basic dictionary ref WITH THE SAME PROPERTIES ALL THE TIME.
// If ONE of the properties doesn't match, you will get SecItemCopyMatching fails etc.
CFMutableDictionaryRef CreateDefaultSECKEYDictionary( CFDataRef keyChainId );

// addressOfItem should be a pointer to a pointer.
// For example, SecKeyRef is actually type __SecKeyRef*,
// and if you take &SecKeyRef that will be a double pointer.
CFArrayRef CFArrayCreateWithItem( void* addressOfItem );

// Sec* helper functions
extern const char *SecTrustResultName[];

bool SecCheck( OSStatus res, const char* msg );

// 1. Loading a SecCertificateRef from a path.
SecCertificateRef SecCertificateFromPath( NSString* certPATH );

// 2. Saving your loaded certificate in keychain, with a certain keyChainId.
bool SecCertificateSaveInKeyChain( SecCertificateRef cert, CFDataRef keyChainId );

// 3. Creating a SecKeyRef from a loaded Certificate (either that
//    was loaded from disk, or loaded from Keychain.)
SecKeyRef SecKeyFromCertificate( SecCertificateRef cert );

// 4. Loading a SecKey from a Certificate that was
//    previously stored in Keychain.
SecKeyRef SecKeyFromKeyChain( CFDataRef keyChainId );

// 5. Easiest method to use: SecKeyFromPath, which
//    goes CERTPATH => CERTIFICATE => SECKEY
SecKeyRef SecKeyFromPathAndSaveInKeyChain( NSString* certPATH, CFDataRef keyChainId );

// 6. You can also delete a key from the keychain if need be.
bool SecCertificateDeleteFromKeyChain( CFDataRef keyChainId );

void SecCertificatePrintInfo( SecCertificateRef cert );


#endif