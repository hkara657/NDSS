#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>


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

  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, key, iv))
    handleErrors();

  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

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

  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, key, iv))
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

int conv(unsigned char c)
{
	if(c>='0' && c<='9')
		return c-'0';
	else if(c>='a' && c<='f')
		return c-'a'+10;
}

char revconv(unsigned int c)
{
	if(c>=0 && c<=9)
		return c+'0';
	else
		return (c-10)+'a';
}


void parse_hex(unsigned char *inp,int len,unsigned char *pt)
{
	int i,j=0;
	for(i=0;i<len;i+=2)
	{
		pt[j++] = (conv(inp[i])*16)+conv(inp[i+1]);
	}
	pt[j]=0;
}

void output_hex(unsigned char *pt,int len,unsigned char *out)
{
	int i,j=0;
	for(i=0;i<len;i++)
	{
		unsigned char tp = pt[i];
		int x = tp/16;
		int y = tp%16;
		out[j++] = revconv(x);
		out[j++] = revconv(y);
	}
	out[j]=0;
}


unsigned char tp_key[10][256]={
	"d7d57bd847154af9722a8df096e61a42",
	"c9f4ce21b4c7daaa4f93e292dc605bc5",
	"7a70cc6b261eeccb05c57117d5763197",
	"85dbd5a6e73681a51a4a7d4e93ca7d0c"};
unsigned char tp_iv[10][256]={"fdde201c91e401d9723868c2a612b77a","5e5a8cf2808c720e01c1ed92d470a45d","bb7b9667fbd76d5ee204828769a341b1","89d897c5aa9e0a5d5586d4b4664fc927"};
unsigned char inp[10][256]={
	"81883f22165282ba6a442a8dd2a768d4",
	"8e19c5cacd015a662e7f40cdecadbf79a68081c06d9544b41c2dd248e77633b4",
	"823cbaae3760c85512a3c83fd60bb54b7cfc739b295b63e05ef435d86e19fd15368c89ff08a0f21ce89a728ffb5d75df",
	"e3dbfc6ae1a879870fd22644c8135fe063355dfc0a8dad45c9c6e052e6e085cf717754dc1b49acb04cf340826ffb0da991138f022a9c34923a6a116c98c7d3d5"};

unsigned char exp_out[10][256]={
	"84cc130b6867623696aa8f523d968ade",
	"885dc48add7ee6a1839bc5c5e03beae071301ecf91a0111520cde0d3a112f5d2",
	"f5c49aae8a026bf05e525a12ab7e195eea8a1b71a8d32a5113aa8974858f2cfc0339805003a0cb1a7be19f376d4604eb",
	"48a34bd814dd4e1b92a5aa04218136bcd428fd34ca151a78e0eb2c8f24d4f070978aacd5e1351c909c818db45d25b34fc21cb06a3984f969ab825ef795888da9"};

unsigned char ciphertext[256];
unsigned char out[256];




int main (void)
{
	int no_of_samples = 4;
	int i;
	unsigned char key[256],iv[128],plaintext[128];
	
	for(i=0;i<no_of_samples;i++)
	{
		
		int key_len=strlen(tp_key[i])/2;
		int iv_len=strlen(tp_iv[i])/2;
		int pt_len=strlen(inp[i])/2;
		int ciphertext_len;

		parse_hex(tp_key[i],key_len*2,key);
		parse_hex(tp_iv[i],iv_len*2,iv);
		parse_hex(inp[i],pt_len*2,plaintext);

		/* Initialise the library */
		ERR_load_crypto_strings();
		OpenSSL_add_all_algorithms();
		OPENSSL_config(NULL);

		/* Encrypt the plaintext */
		ciphertext_len = encrypt (plaintext, pt_len, key, iv, ciphertext);
		output_hex(ciphertext,ciphertext_len,out);
		
		printf("KEY          =   %s\n",tp_key[i]);
		printf("IV           =   %s\n",tp_iv[i]);
		printf("PLAINTEXT    =   %s\n",inp[i]);
		printf("CIPHERTEXT   =   %s\n",out);
		
		if(strcmp(out,exp_out[i])==0)
			printf("Test Passed\n");
		else
			printf("Test Failed\n");
		printf("\n\n");
		
				
		/* Clean up */
		EVP_cleanup();
		ERR_free_strings();
		
	}

  return 0;
}
