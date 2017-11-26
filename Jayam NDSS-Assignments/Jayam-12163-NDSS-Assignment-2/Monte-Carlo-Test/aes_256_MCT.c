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


unsigned char tp_key[256]={"b46129976d3fb9a83b10d3f6bb928a5b2e8fd00ec10fdf7513ccd83af1e6aaa1"};
unsigned char tp_iv[256]={"39c6a3ab26ae170921c503fc62ec0ba9"};
unsigned char inp[256]={"7a644b53ef2cb607328c63dd61321515"};
unsigned char exp_out[256] = {"5fe7772bc8807a9fcb5f35cf23ef3c73"};

unsigned char out[256],cur_iv[256];


int main (void)
{
	int no_of_samples = 1;
	int i,j,k,l;
	unsigned char key[105][256],iv[105][128],plaintext[1005][128],ciphertext[1005][256];
	
	int key_len=strlen(tp_key)/2;
	int iv_len=strlen(tp_iv)/2;
	int pt_len=strlen(inp)/2;
	int ciphertext_len;

	parse_hex(tp_key,key_len*2,key[0]);
	parse_hex(tp_iv,iv_len*2,iv[0]);
	parse_hex(inp,pt_len*2,plaintext[0]);

	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	/* Encrypt the plaintext */
	
	for(i=0;i<100;i++)
	{
		if(i<5 || i==99)
		{
			printf("COUNT = %d\n",i);
			output_hex(key[i],key_len,out);
			printf("KEY          =   %s\n",out);
			output_hex(iv[i],iv_len,out);
			printf("IV           =   %s\n",out);
			output_hex(plaintext[0],pt_len,out);
			printf("PLAINTEXT    =   %s\n",out);		
		}
		
		for(l=0;l<iv_len;l++)
			cur_iv[l]=iv[i][l];

		//~ if(i<3)
			//~ printf("\n");

		for(j=0;j<1000;j++)
		{
			ciphertext_len = encrypt (plaintext[j], pt_len, key[i], cur_iv, ciphertext[j]);


//////////////////// uncomment to print intermediate values  /////////////////////////			
				//~ if(i<3 && j<5)
				//~ {
	//~ //				printf("%d %d\n",pt_len,ciphertext_len);
					//~ output_hex(ciphertext[j],ciphertext_len,out);
					//~ printf("%s\n",out);
				//~ }

			for(l=0;l<iv_len;l++)
				cur_iv[l]=plaintext[j][l]^ciphertext[j][l];
			
			if(j==0)
				memcpy(plaintext[j+1],iv[i],pt_len*sizeof(unsigned char));
			else
				memcpy(plaintext[j+1],ciphertext[j-1],pt_len*sizeof(unsigned char));

		}
		j--;
		if(i<5 || i==99)
		{
			output_hex(ciphertext[j],ciphertext_len,out);
			printf("CIPHERTEXT   =   %s\n\n",out);
		}
		
		for(l=0;l<pt_len;l++)
			key[i+1][l]=key[i][l]^ciphertext[j-1][l];
		for(k=0;l<key_len;l++,k++)
			key[i+1][l]=key[i][l]^ciphertext[j][k];
		
		for(l=0;l<iv_len;l++)
			iv[i+1][l]=ciphertext[j][l];
		for(l=0;l<pt_len;l++)
			plaintext[0][l]=ciphertext[j-1][l];
		
	}
	
	if(strcmp(out,exp_out)==0)
		printf("Test Passed\n");
	else
		printf("Test Failed\n");
	printf("\n\n");

			
	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();
	
  return 0;
}
