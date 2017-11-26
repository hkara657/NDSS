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

  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, key, iv))
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

  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, key, iv))
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
	"6f419b4c683a44d67d234eaa6b57f622f912de657dddb280a14d0cb967ed951f",
	"a92577607968dbeee135a24edc2f3263926d97141f2c6d9f96c0012f45d1b3b0",
	"c4c7fad6535cb8714a5c40779a8ba1d2533e23b4b258732a5b7801f4e371a794",
	"7c4424cf1ac4d75aceebdb2238a9f0383438f453afa55772b98ccfc3dc234dc4"};
unsigned char tp_iv[10][256]={"19b888800ff1d0116124f79dfae54ffe","97bfebec0c2e7704d002dc6a1fd36901","5eb93313b871ff16b98a9bcb43330d6f","34838273c7848b70c6e1abad79ce1325"};
unsigned char inp[10][256]={
	"3d12989faf41ba75bfa70e2bcc2fa222",
	"bb28705ef9e5151afc73e3886f25f52175dbb57ae36eacc5ac4e989b9d69bff9",
	"6d0bb079638471e939d4531486c14c259aeec6f3c00dfdd6c050a8baa820db71cc122c4e0c1715ef55f3995a6bf02a4c",
	"cb9ac89b78902ce09d8467291181a702fd9a0430e2dca944de8135702b66619ae8c0e2af1c0a913af842c9355c54101e9dd7fa4e86f74b879cb25ccca648c075"};

unsigned char exp_out[10][256]={
	"2d6b005e8d3bc6ea9f62dca36d47aea5",
	"944169b510b2825505a14b22eaba744c19ee30da6ed697e3b879425f26808289",
	"0f54617159d03ffc1bfafb602930d700f4a4a8e6dd93944664d219c4c54dde1b0453e173f51874aefd64a2e1e27613b0",
	"5df03b8d91cb0e5da86ba108ead87ec762c90767ace96be60598b4efe8f3d3f8383827a599180ffdddb3e94151e22feeda3c90651a697f3834e036e44d0506b2"};

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
