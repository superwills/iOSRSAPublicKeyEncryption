#import "ViewController.h"

#include "/usr/include/base64.h" // https://github.com/superwills/NibbleAndAHalf/blob/master/NibbleAndAHalf/base64.h


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


static const UInt8 keychainIdString[] = "com.example.widgets.publickey\0" ; //MAKE SURE THIS IS NULL TERMINATED
// THIS EXAMPLE RELIES ON THAT FOR PRINTING

CFDataRef CFKEYCHAINID ;

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
  CFDictionaryAddValue( dic, kSecClass, kSecClassKey ) ;
  CFDictionaryAddValue( dic, kSecAttrApplicationTag, keyChainId ) ;
	CFDictionaryAddValue( dic, kSecAttrKeyType, kSecAttrKeyTypeRSA ) ;
  //CFDictionaryAddValue( dic, kSecReturnPersistentRef, kCFBooleanTrue ) ; // This makes some things fail. Leave it off
  // and work in local program memory space.
  return dic ;
}

CFArrayRef CFArrayCreateWithItem( void* addressOfItem )
{
  return CFArrayCreate( 0, addressOfItem, 1, &kCFTypeArrayCallBacks ) ;
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

void test()
{
  
  //////// THIS HAPPENS FIRST OR ALL WILL FAIL
  CFKEYCHAINID = CFDataCreate( 0, keychainIdString, sizeof( keychainIdString) ); // USE THIS
  
  //SecCertificateDeleteFromKeyChain( CFKEYCHAINID ) ;
  
  SecKeyRef PUBLICKEY = SecKeyFromKeyChain( CFKEYCHAINID ) ;
  if( PUBLICKEY )  puts( "<< KEY RETRIEVAL FROM KEYCHAIN OK!! >>" ) ;
  else
  {
    puts( "FAILED TO LOAD SECKEY FROM KEYCHAIN!!!!!" ) ;
    puts( "Loading from certificate.cer.." ) ;
    
    // LOAD THE PUBLIC KEY FROM certificate.cer.
    NSString* certPath = [[NSBundle mainBundle] pathForResource:@"certificate" ofType:@"cer"];
    PUBLICKEY = SecKeyFromPathAndSaveInKeyChain( certPath, CFKEYCHAINID ) ;  //SecKeyFromPath( certPath ) ;
    if( !PUBLICKEY )
    {
      puts( "DOUBLE FAIL!!!!!  MAKE SURE YOU HAVE LOADED certificate.cer INTO THE XCODE PROJECT "
      "AND THAT IT IS SET UNDER 'COPY BUNDLE RESOURCES'!!!" ) ;
      return ;
    }
  }
  
  
  
  int blockSize = SecKeyGetBlockSize( PUBLICKEY ) ;
  printf( "THE MAX LENGTH OF DATA I CAN ENCRYPT IS %d BYTES\n", blockSize ) ;
  
  uint8_t *binaryData = (uint8_t *)malloc( blockSize ) ;
  for( int i = 0 ; i < blockSize ; i++ )
    binaryData[i] = 'A' + (i % 26 ) ; // loop the alphabet
  binaryData[ blockSize-1 ] = 0 ; // NULL TERMINATED ;)
  printf( "ORIGINAL DATA:\n%s\n", (char*)binaryData ) ;

  uint8_t *encrypted = (uint8_t *)malloc( blockSize ) ;
  size_t encryptedLen ;
  SecCheck( SecKeyEncrypt( PUBLICKEY, kSecPaddingNone, binaryData, blockSize, encrypted, &encryptedLen ), 
    "SecKeyEncrypt" ) ;
  free( binaryData ) ;
  
  printf( "ENCODED %d bytes => %lu bytes\n", blockSize, encryptedLen ) ;
  
  int base64DataLen ;
  char* base64Data = base64( encrypted, encryptedLen, &base64DataLen ) ;
  printf( "B64( ENCRYPTED( <<BINARY DATA>> ) ) as %d base64 ascii chrs:\n%s\n", base64DataLen, base64Data ) ;
  free( encrypted ) ;
  
  
  /// SEND base64Data across the net.

}




@implementation ViewController

















- (void)viewDidLoad
{
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}

- (void)viewDidUnload
{
    [super viewDidUnload];
    // Release any retained subviews of the main view.
    // e.g. self.myOutlet = nil;
}

- (void)viewWillAppear:(BOOL)animated
{
  [super viewWillAppear:animated];
  test() ;
  //[self testAsymmetricEncryptionAndDecryption];
  
}

- (void)viewDidAppear:(BOOL)animated
{
  [super viewDidAppear:animated];
}

- (void)viewWillDisappear:(BOOL)animated
{
  [super viewWillDisappear:animated];
}

- (void)viewDidDisappear:(BOOL)animated
{
  [super viewDidDisappear:animated];
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
  // Return YES for supported orientations
  if ([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPhone)
    return (interfaceOrientation != UIInterfaceOrientationPortraitUpsideDown);
  else return YES;

}

- (void)didReceiveMemoryWarning
{
  [super didReceiveMemoryWarning];
  // Release any cached data, images, etc that aren't in use.
}





@end