#ifndef SECKEYHELPER_H
#define SECKEYHELPER_H

/*

The code in this package is released under the ZLib license.

https://github.com/superwills/iOSRSAPublicKeyEncryption
SecKeyHelper.h -- iOS public key helper functions
version 1.0.0, April 21, 2013 11:47a
version 1.0.1, Oct 11, 2013 2:10p /+ SecCRUD* operations


Copyright (C) 2013 William Sherif

This software is provided 'as-is', without any express or implied
warranty.  In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.

William Sherif

*/

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



// Additional Sec* operations for CRUD data storage and retrieval (simple binary data)
CFMutableDictionaryRef getKeylookup( const char* keyname ) ;

// provides serialization and deserialization for static types
template <typename T>
bool SecCreate( const char* keyname, const T* data )
{
  CFMutableDictionaryRef keyLookup = getKeylookup( keyname ) ;
  CFDataRef cfData = CFDataCreate( 0, (const UInt8*)data, sizeof(T) ) ;
  
  // store binary data (any CFDataRef) in kSecAttrGeneric
  // for a kSecClassGenericPassword type keychain entry
  CFDictionaryAddValue( keyLookup, kSecAttrGeneric, cfData ) ;// the actual data we want to store.
  bool success = SecCheck( SecItemAdd( keyLookup, NULL ), "SecItemAdd" ) ;
  CFRelease( cfData ) ;
  CFRelease( keyLookup ) ;
  return success ;
}

// You should know the len, as sizeof(T)
template <typename T>
bool SecRead( const char* keyname, T* data )
{
  CFMutableDictionaryRef keyLookup = getKeylookup( keyname ) ;
  CFDictionaryAddValue( keyLookup, kSecReturnAttributes, kCFBooleanTrue ) ; // makes it return a DICTIONARY
  CFMutableDictionaryRef dataFromKeychain ;
  OSStatus res = SecItemCopyMatching( keyLookup, (CFTypeRef *)&dataFromKeychain ) ;
  CFRelease( keyLookup ) ;
  
  bool success = 0 ;
  
  if( res == noErr )
  {
    CFDataRef cfData = (CFDataRef)CFDictionaryGetValue( dataFromKeychain, kSecAttrGeneric ) ; // the cfData doesn't need CFRELEASE
    // because it is just GETVALUE, NOT CREATE or COPY.  See http://stackoverflow.com/questions/10203990/
    
    const UInt8* datFromKC = CFDataGetBytePtr( cfData ) ;
    if( cfData )
    {
      success = 1 ; // we succeeded in retrieving the data
      memcpy( data, datFromKC, sizeof( T ) ) ; // copy sizeof(T) bytes.
      // you're responsible to alloc `data`'s memory space.
    }
    else { puts( "ERR: kSecAttrGeneric field not set, no CFData" ) ; } // record found, but the kSecAttrGeneric field was not set
    
    CFRelease( dataFromKeychain ) ;
    return success ; // ok
  } //else {} // OTHER ERROR, such as NOT FOUND
  
  return success ; 
}

// Attempts to update, fails if row didn't exist (so creates it)
template <typename T>
bool SecUpdate( const char* keyname, const T* data )
{
  CFMutableDictionaryRef keyLookup = getKeylookup( keyname ) ;

  // wrap the kvp to change in a dictionary
  CFDataRef cfData = CFDataCreate( 0, (const UInt8*)data, sizeof(T) ) ;
  CFMutableDictionaryRef dataAttrib = CFMutableDictionaryCreateEmpty() ;
  CFDictionaryAddValue( dataAttrib, kSecAttrGeneric, cfData ) ;
  
  bool success = SecCheck( SecItemUpdate( keyLookup, dataAttrib ), "SecItemUpdate" ) ;
  CFRelease( keyLookup ) ;
  CFRelease( dataAttrib ) ;
  CFRelease( cfData ) ;
  
  return success ;
}

bool SecDelete( const char* keyname ) ;


#endif
