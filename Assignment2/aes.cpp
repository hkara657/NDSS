#include<bits/stdc++.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
using namespace std;

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

int main()
{
	unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
	unsigned char *iv = (unsigned char *)"0123456789012345";
	unsigned char *plaintext = (unsigned char *)"The quick brown fox jumps over the lazy dog";
	unsigned char ciphertext[128]={0};

	/* Buffer for the decrypted text */
	unsigned char decryptedtext[128];

	int decryptedtext_len, ciphertext_len;
  
	ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,ciphertext);
    
    ciphertext[ciphertext_len]='\0';
    
    std::cout << "a = " << typeid(std::bitset<8>(5)).name()  << std::endl;
    std::cout << "a = " << std::bitset<16>(511)  << std::endl;
    //cout<<ciphertext_len<<"\n";
    int i=0;
    while(ciphertext[i] && i<5)
    {
		int n=(int)ciphertext[i];
		cout<<std::hex<<n<<"\n"<<std::bitset<16>(n)<<"\n"<<std::bitset<16>(n^(511))<<"\n#####\n";
		i++;
	}
    //~ cout<<"raw cipher text is \n"<<ciphertext<<"\n#########\n";
	//~ printf("Ciphertext is:\n");
	//~ BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);	
	
	
	
	//~ //###############33
	//~ decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
    //~ decryptedtext);

	//~ /* Add a NULL terminator. We are expecting printable text */
	//~ decryptedtext[decryptedtext_len] = '\0';

	//~ /* Show the decrypted text */
	//~ printf("Decrypted text is:\n");
	//~ printf("%s\n", decryptedtext);


	
	

}
