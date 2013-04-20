iOSRSAPublicKeyEncryption describes how to encrypt data from a PUBLIC KEY in iOS using RSA.

The main functions are in [SecKeyHelper.h](https://github.com/superwills/iOSRSAPublicKeyEncryption/blob/master/iOSRSA/SecKeyHelper.h):

    // Loads a certificate located at certPATH (usually in your bundle)
    SecKeyRef SecKeyFromPathAndSaveInKeyChain( NSString* certPATH, CFDataRef keyChainId )
    
    // Loads a SecKeyRef from Keychain (that you previously loaded from some certPATH)
    SecKeyRef SecKeyFromKeyChain( CFDataRef keyChainId )
    


>       FACTS      

1) YOU'RE NOT SUPPOSED TO LOAD PUBLIC KEYS IN IOS FROM 
   ANYTHING OTHER THAN A "CERTIFICATE".  NO BASE64 ENCODED
   ----- BEGIN PUBLIC KEY ------ STRINGS ARE SUPPORTED ON IOS BY DEFAULT.
   
2) CERTIFICATES ARE EASY TO CREATE USING OpenSSL OR certutil ON WINDOWS
The basic steps are:


            HOW TO MAKE A CERTIFICATE


### Make the -----RSA PRIVATE KEY----- file in PEM format
    $ openssl genrsa -out privKey.pem 2048

### Make the -----CERTIFICATE REQUEST-----
    $ openssl req -new -key privKey.pem -out certReq.pem

### Make the actual -----CERTIFICATE-----
    $ openssl x509 -req -days 2000 -in certReq.pem -signkey privKey.pem -out tificate.pem

### Make the DER certificate.crt file from the certificate.pem
    $ openssl x509 -outform der -in certificate.pem -out certificate.cer

SEE ALSO: [stackoverflow](http://stackoverflow.com/questions/9728799/using-an-rsa-public-key-on-/16096064#16096064)
SEE ALSO: [OpenSSL HOWTO](http://www.openssl.org/docs/HOWTO/certificates.txt)

DO NOT FOLLOW [WINGOFHERMES' METHOD](http://blog.wingsofhermes.org/?p=75)
FOR LOADING PUBLIC KEYS FROM BASE64 CODED STRINGS.
THIS IS NOT SUPPORTED FOR A __REASON__ AND IS NOT THE RECOMMENDED CODE PATH.

YOU'VE BEEN WARNED.

RELEVANT DEVFORUMS.APPLE THREADS:

1) [USE CERTIFICATES](https://devforums.apple.com/message/135272#135272):
> In general we recommend that you distribute key material to
clients as either a certificate (for public keys) or a PKCS#12
(for private keys or identities).  iPhone OS has good support
for importing these types of data.

2) [IF YOU HAVE THE DER DATA, YOU CAN CREATE A CERTIFICATE](https://devforums.apple.com/message/135288#135288)
> If you have a blob of data in DER form, you can create a SecCertificateRef
from it using SecCertificateCreateWithData.  Once you have a certificate ref,
you can extract the public key using SecTrustCopyPublicKey.
There's one gotcha with this, as explained in the following post.
https://devforums.apple.com/message/114555#114555

3) [HOW TO LOAD A CERTIFICATE](https://devforums.apple.com/message/114555#114555)
> This is surprisingly easy.  You don't need to add the certificate
to the keychain to handle this case.  Rather, just load the
certificate data (that is, the contents of a .cer file) in 
your application (you can either get this from your bundle 
or off the network) and then create a certificate ref using 
SecCertificateCreateWithData.  From there you can extract a 
public key ref using a SecTrust object (SecTrustCreateWithCertificates, 
SecTrustEvaluate -- you can choose to ignore the resulting 
SecTrustResultType -- and SecTrustCopyPublicKey).  
And from there you can encrypt and verify using the
SecKey APIs (SecKeyEncrypt, SecKeyRawVerify).

