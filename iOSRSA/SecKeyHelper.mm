#import "SecKeyHelper.h"

//  The base ctor is too large.
CFMutableDictionaryRef CFMutableDictionaryCreateEmpty()
{
  return CFDictionaryCreateMutable( 0, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks ) ;
}

// We have to create the basic dictionary ref WITH THE SAME PROPERTIES ALL THE TIME.
// If ONE of the properties doesn't match, you will get SecItemCopyMatching fails etc.
CFMutableDictionaryRef CreateDefaultSECKEYDictionary( CFDataRef keyChainId )
{
  CFMutableDictionaryRef dic = CFMutableDictionaryCreateEmpty() ;
  
  // The kSecClass can be 1 of 5 types, kSecClassKey is to be used for cryptographic KEYS.
  // see the header defn for kSecClassKey and http://stackoverflow.com/questions/11614047/what-makes-a-keychain-item-unique-in-ios
  CFDictionaryAddValue( dic, kSecClass, kSecClassKey ) ;
  
  // Set up the application identifier tag, so keychain knows this key
  // is associated with our app.  `keyChainId` is called `keychainIdStr`
  // (defined in ViewController.m).  You just use the same application tag
  // for all keychain items that belong to the same app.  The application tag
  // is like a KEYRING, __metaphorically speaking__.
  CFDictionaryAddValue( dic, kSecAttrApplicationTag, keyChainId ) ;
  
  // Now I tell you the TYPE of the key being RSA, (as opposed to kSecAttrKeyTypeEC,
  // which would be an "elliptic curve" encryption type key (which I've never heard of prior to looking it up here)).
	CFDictionaryAddValue( dic, kSecAttrKeyType, kSecAttrKeyTypeRSA ) ;
  
  //CFDictionaryAddValue( dic, kSecReturnPersistentRef, kCFBooleanTrue ) ; // This makes some things fail. Leave it off
  // and work in local program memory space.
  return dic ;
}

// addressOfItem should be a pointer to a pointer.
// For example, SecKeyRef is actually type __SecKeyRef*,
// and if you take &SecKeyRef that will be a double pointer.
CFArrayRef CFArrayCreateWithItem( void* addressOfItem )
{
  return CFArrayCreate( 0, (const void**)addressOfItem, 1, &kCFTypeArrayCallBacks ) ;
}

// Sec* helper functions
const char *SecTrustResultName[]={
  "kSecTrustResultInvalid",
  "kSecTrustResultProceed",
  "kSecTrustResultConfirm",
  "kSecTrustResultDeny",
  "kSecTrustResultUnspecified",
  "kSecTrustResultRecoverableTrustFailure",
  "kSecTrustResultFatalTrustFailure",
  "kSecTrustResultOtherError"
} ;

bool SecCheck( OSStatus res, const char* msg )
{
  if( res==errSecSuccess )
  {
    printf( "< %s okie dokie >\n", msg ) ; // COMMENT THIS OUT TO SILENCE OK's
  }
  else
  {
    printf( "< NOT OK!! >: %s FAILED:\n  >> ", msg ) ; 
    switch( res )
    {
    case errSecUnimplemented:
      puts( "errSecUnimplemented: Function or operation not implemented." ) ; break;
    case errSecParam:
      puts( "errSecParam: One or more parameters passed to a function where not valid." ) ; break;
    case errSecAllocate:
      puts( "errSecAllocate: Failed to allocate memory." ) ; break;
    case errSecNotAvailable:
      puts( "errSecNotAvailable: No keychain is available. You may need to restart your computer." ) ; break;
    case errSecDuplicateItem:
      puts( "errSecDuplicateItem: The specified item already exists in the keychain." ) ; break;
    case errSecItemNotFound:
      puts( "errSecItemNotFound: The specified item could not be found in the keychain." ) ; break;
    case errSecInteractionNotAllowed:
      puts( "errSecInteractionNotAllowed: User interaction is not allowed." ) ; break;
    case errSecDecode:
      puts( "errSecDecode: Unable to decode the provided data." ) ; break;
    case errSecAuthFailed:
      puts( "errSecAuthFailed: The user name or passphrase you entered is not correct." ) ; break;
    default:
      puts( "UNDEFINED ERROR" ) ;  break;
    }
  }
  return res == errSecSuccess ;
}

// 1. Loading a SecCertificateRef from a path.
SecCertificateRef SecCertificateFromPath( NSString* certPATH )
{
  NSData* certData = [NSData dataWithContentsOfFile:certPATH];
  if( ![certData length] ) {
    puts( "ERROR: certData length was 0" ) ;
    return NULL ;
  }
  
  SecCertificateRef cert = SecCertificateCreateWithData( NULL, (__bridge CFDataRef)certData ) ;
  if( !cert )
  {
    puts( "ERROR: SecCertificateCreateWithData failed" ) ;
    return NULL ;
  }
  
  return cert ;
}

// 2. Saving your loaded certificate in keychain, with a certain keyChainId.
bool SecCertificateSaveInKeyChain( SecCertificateRef cert, CFDataRef keyChainId )
{
  printf( "Adding `%s` to keychain..\n", CFDataGetBytePtr( keyChainId ) ) ;
  // First you make a DICTIONARY. It's not to look up security definitions like "what is AES"
  // but instead to define a set of {key:value} pairs (just like json)
	
  // I much prefer the syntax of CFDictionary here.  It is SO much cleaner,
  // plus insertion goes "key, value" as opposed to value: forKey.
  CFMutableDictionaryRef dic = CreateDefaultSECKEYDictionary( keyChainId ) ;
  
  CFDataRef CERTDATA = SecCertificateCopyData( cert ) ;
  // Now add to that the certificate data.
  CFDictionaryAddValue( dic, kSecValueData, CERTDATA ) ;
  CFRelease( CERTDATA ) ;
  
	CFTypeRef persistPeer = NULL;
	return SecCheck( SecItemAdd(dic, &persistPeer), "SecItemAdd" ) ;
}

// 3. Creating a SecKeyRef from a loaded Certificate (either that
//    was loaded from disk, or loaded from Keychain.)
SecKeyRef SecKeyFromCertificate( SecCertificateRef cert )
{
  CFArrayRef cfArray = CFArrayCreateWithItem( &cert ) ;
  
  SecPolicyRef secPolicyRef = SecPolicyCreateBasicX509() ;
  SecTrustRef secTrustRef ;
  SecCheck( SecTrustCreateWithCertificates( cfArray, secPolicyRef, &secTrustRef ), "SecTrustCreateWithCertificates" ) ;
  CFRelease( cfArray ) ;
  
  SecTrustResultType secTrustResult ;
  SecCheck( SecTrustEvaluate( secTrustRef, &secTrustResult ), "SecTrustEvaluate" ) ;
  
  printf( "SecTrustEvaluate RESULT: %s\n", SecTrustResultName[secTrustResult] ) ;

  SecKeyRef SECKEY = SecTrustCopyPublicKey( secTrustRef ) ;
  if( !SECKEY )
    puts( "ERROR: SecTrustCopyPublicKey failed" ) ;
  
  return SECKEY ;
}

// 4. Loading a SecKey from a Certificate that was
//    previously stored in Keychain.
SecKeyRef SecKeyFromKeyChain( CFDataRef keyChainId )
{
  printf( "Attempting to retrieve key `%s` from keychain..\n", CFDataGetBytePtr( keyChainId ) ) ;
  
  CFMutableDictionaryRef dic = CreateDefaultSECKEYDictionary( keyChainId ) ;
  CFDictionaryAddValue( dic, kSecReturnData, kCFBooleanTrue ) ;
  
  CFDataRef certDATA ;
  if( !SecCheck( SecItemCopyMatching( dic, (CFTypeRef *)&certDATA), "SecItemCopyMatching" ) )
    return NULL ; // NO KEY!
  
  SecCertificateRef cert = SecCertificateCreateWithData( 0, certDATA ) ;
  if( !cert )
  {
    puts( "ERROR: Your 'certificate data' is NOT a valid DER-encoded X.509 certificate" ) ;
    return NULL ;
  }
  return SecKeyFromCertificate( cert ) ;
}

// 5. Easiest method to use: SecKeyFromPath, which
//    goes CERTPATH => CERTIFICATE => SECKEY
SecKeyRef SecKeyFromPathAndSaveInKeyChain( NSString* certPATH, CFDataRef keyChainId )
{
  SecCertificateRef cert = SecCertificateFromPath( certPATH ) ;
  
  if( !cert )
  {
    printf( "ERROR: Could not load certificate at path `%s`,"
      "Are you sure you added it to the XCode workspace?\n", [certPATH UTF8String] ) ;
    return NULL ;
  }
  
  // SAVE IT in keychain
  SecCertificateSaveInKeyChain( cert, keyChainId ) ;
  
  return SecKeyFromCertificate( cert ) ;
}

// 6. You can also delete a key from the keychain if need be.
bool SecCertificateDeleteFromKeyChain( CFDataRef keyChainId )
{
  printf( "DELETING ITEM `%s`\n", CFDataGetBytePtr(keyChainId) ) ;
  CFMutableDictionaryRef dic = CreateDefaultSECKEYDictionary( keyChainId ) ;
  return SecCheck( SecItemDelete(dic), "SecItemDelete" ) ;
}

void SecCertificatePrintInfo( SecCertificateRef cert )
{
  CFStringRef certSummary = SecCertificateCopySubjectSummary( cert );
  printf( "Certificate summary: %s\n", CFStringGetCStringPtr( certSummary, kCFStringEncodingMacRoman ) ) ;
  CFRelease(certSummary);
}






// Additional Sec* operations for CRUD data storage and retrieval (simple binary data)
CFMutableDictionaryRef getKeylookup( const char* keyname )
{
  CFMutableDictionaryRef keyLookup = CFMutableDictionaryCreateEmpty() ;
  CFDictionaryAddValue( keyLookup, kSecClass, kSecClassGenericPassword ) ; // "generic password" for arbitrary binary data
  CFStringRef cfAccount = CFStringCreateWithCString( NULL, keyname, kCFStringEncodingMacRoman ) ;
  CFDictionaryAddValue( keyLookup, kSecAttrAccount, cfAccount ) ;   // uniquely identify the row.
  CFRelease( cfAccount ) ;
  return keyLookup ;
}

bool SecDelete( const char* keyname )
{
  CFMutableDictionaryRef keyLookup = getKeylookup( keyname ) ;
  bool success = SecCheck( SecItemDelete( keyLookup ), "SecItemDelete" ) ;
  CFRelease( keyLookup ) ;
  return success ;
}


