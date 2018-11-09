/*This code is built with heavy copying from examples from the openssl
  wiki, along with examples from openssl man pages*/

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <string.h>
//--------------------------
// compile with
// gcc cryptotest.c -lcrypto -o cryptotest
//--------------------------

//--------------------------
// generate private key first
// openssl genpkey -algorithm RSA -out RSApriv.pem -pkeyopt rsa_keygen_bits:2048
// generate public key using private key
// openssl rsa -pubout -in RSApriv.pem -out RSApub.pem
//--------------------------

//--------------------------
// use symmetric key to encrypt symmetric key, send over, use symmetric key
// afterwards

// Server starts off knowing a private key
// Clients start off knowing a public key that matches with private key
// Public key can be public to everyone
// Use public key to encrypt, private key to decrypt
//    Doesn't hurt for anyone to encrypt a message
//    So, all clients can encrypt messages, server can decrypt

// Our project won't need to generate keys, just read from files

// Nobody sends long or many messages using asymmetric encryption
//    Because it's very inefficient
//--------------------------

//--------------------------
// What we want is for the client and the server to have symmetric keys that
// they can use in a symmetric key algorithm.
// Correct thing to do is to make client create a symmetric key.
//    STEPS:
//    client1 connects to server, create symmmetric key s1.
//    c1 wants to share symmetric key with server, but not in cleartext
//    c1 encrypts s1 using its public key.
//    c1 sends encrypted symmetric key to server.
//    server uses private key to decrypt symmetric key.
//    Afer this, discard public and private keys; all encryption is now done
//    with symmetric key.
//--------------------------

//--------------------------
// Problem with above system:
// What is hackers take over the server?  They'll see everything
// Real chat programs avoid this, but we won't worry about it

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

//used to encrypt the symmetric, generated key from the client
// uses public key to encrypt
int rsa_encrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){ 
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key, NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_encrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}

//used to decrypt the symmetric, generated key from the client
// uses the private key to encrypt
// technically the private and public keys could be flipped but tat would be pointless and unsecure lol

// a wrapper function: use as is easiest way (may use inside functions yourself)
int rsa_decrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){ 
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key,NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_decrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}

//Used to encrypt messages
//uses the symmeteric key
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

//Used to decrypt messages
//uses the symmeteric key
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	    unsigned char *iv, unsigned char *plaintext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

// takes a msg, encrypts and dec right away
// non standard lib functions used
// integrate with chat program:
int main(void){
  // Public key
  unsigned char *pubfilename = "RSApub.pem";
  // Private key
  unsigned char *privfilename = "RSApriv.pem";
  unsigned char key[32];
  unsigned char iv[16];
  unsigned char *plaintext =
    (unsigned char *)"This is a test string to encrypt.";
  unsigned char ciphertext[1024];
  unsigned char decryptedtext[1024];
  int decryptedtext_len, ciphertext_len;
  // Initialize cryptography libraries
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);
  // Fill an array of 32 characters with 32 random bytes to use as
  // symmetric key.
  // Use this function because others may not be random enough.
  // generate random key using good random bytes 
  // (use rand functions from a security lib best practice)
  RAND_bytes(key,32); 
  // Create initialization vector.  Recreate for each message.
  // Why pseudo random?  Because it's only important to have iv different
  // for each message.  Pseudo rand is a little more efficient
  RAND_pseudo_bytes(iv,16);
  EVP_PKEY *pubkey, *privkey;
  // Read public key from file
  FILE* pubf = fopen(pubfilename,"rb");
  pubkey = PEM_read_PUBKEY(pubf,NULL,NULL,NULL);  // read public key
  unsigned char encrypted_key[256];
  // Encrypt symmetric key using public key.
  // key - thing we want to encrypt
  // 32 - length
  // pubkey - public key used to encrypt
  // encrypted_key - where to put result
  int encryptedkey_len = rsa_encrypt(key, 32, pubkey, encrypted_key);
  // Use this to encrypt using symmetric key!
  // plaintext - what to encrypt
  // strlen(---) - length of message
  // key - key used to encrypt
  // iv - initialization vector
  // ciphertext - output buffer, filled with encrypted message
  // Returns length of encrypted message -- not guaranteed to be same length
  // as original message!  Will always be a multiple of 16 bytes
  // enc using a string of bytes (can be any char array), uses lib functions (see above)
  // (what trying to encrypt, len of input (check to make sure will fit buffer length), 
  // key we're using (symmetric key - RSA is assymmetric key), 
  // initiazation vector, where output is going (can't assume encypt text is same 
  // length as original msg (multiple of 16 bytes)))
  // init vector: When enc multiple msgs using a deterministic process will produce 
  // the same result for the same msg. An attacker may be able to learn the same 
  // thing was sent twice, etc.
  // - used to provide some randomness: XOR iv with msg to prevent same msg from 
  // looking the same; must use diff iv to accomplish this; randomly gen a new iv 
  // every msg; send the iv over the 
  // connection in clear text in a header (the key itself provides the secrecy) 
  // so it can be used with key and msg to dec. 
  ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
                            ciphertext);
  printf("Ciphertext is:\n");
  // bio dump for converting binary to hex
  // also includes character representation in case some of the data is text
  BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

  // Read private key
  // open file for private key and read priv key (only s should do this)
  FILE* privf = fopen(privfilename,"rb"); 
  privkey = PEM_read_PrivateKey(privf,NULL,NULL,NULL);
  unsigned char decrypted_key[32];
  // This is what the server would do.
  // enc using priv key (, the length of the key, , output)
  int decryptedkey_len = rsa_decrypt(encrypted_key, encryptedkey_len, privkey, decrypted_key); 
  // Decrypt using symmetric key
  // Need to decrypt using same initialization vector.  How to give iv
  // to server?  Just tack it on to the front, unencrypted.  No harm, because
  // iv isn't meant to prevent decryption -- that's what the key is for.
  // iv is just to prevent patterns from being discovered.
  // ( , , , , decrypted text buffer)
  decryptedtext_len = decrypt(ciphertext, ciphertext_len, decrypted_key, iv,
			      decryptedtext);
  decryptedtext[decryptedtext_len] = '\0';
  printf("Decrypted text is:\n");
  printf("%s\n", decryptedtext);
  EVP_cleanup();
  ERR_free_strings();
  return 0;
}
