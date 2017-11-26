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

  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_192_ofb(), NULL, key, iv))
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


  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_192_ofb(), NULL, key, iv))
    handleErrors();

  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

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
	"2943e3edfa815260a8a697b386ca3ae3eee914f22b3857dc",
	"6a32b19fc5f048a29efe97927e8f91df23390278d4fc81eb",
	"155f12744f6cf7e1f108df341c5e9c02ddd44812b285e46f",
	"66c7d31359eac09056d597816542bffe4bb33e475dfb2d62"};
unsigned char tp_iv[10][256]={"c6995f00318c241217cdc82cf2fa43f9","39776bf5d8965c7b795e3c6f23115cac","855a5899180472427a1002c0ba5a3dff","426042dc81a7a069251972b91fb35058"};
unsigned char inp[10][256]={
	"67e2cf5d63334ae03dbda91100ab781b",
	"e8bc8453a7d47de7a9ccd94385b008693e4645f3179311b4a9a1e09c328012dc",
	"e7efcd84d52e30376d96ace92160e2ce247e4b82748c679d18041887a6b1488e0966d23581efa0cfeb48114d430d9d55",
	"2f2178a285e61932c0b75d7be0a6e23afe78248330fc8bb3ad9ca9a73232bc2ba41d7bb5f6930f544d385fe362f0908228f2cc47b01f43304991705ceb769e7b"};

unsigned char exp_out[10][256]={
	"225e8bfb133c4332ba6e95ddb841370d",
	"18132430a50b89c64c72c5d9092d8bfb844291799d70151690ca85837d89a79d",
	"d6079c22d740637b24fd801eb02ab24e6d0f32a9ae7c0eafb13b5fcfdf05e1811c2ed7f337e1b964ed0da10990b50de6",
	"863aa235c8ec3d7e8b24244f9eb797a610d0814cf15b2bdc2b17e90e02e15e2b4b73affc0d5983aa9e9b63fc5004629b1e337129cd3e4f3cc48b7f174544e30e"};

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
