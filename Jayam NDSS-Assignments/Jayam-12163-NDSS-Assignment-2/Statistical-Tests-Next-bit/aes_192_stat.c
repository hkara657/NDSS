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

void hex_to_bin(unsigned char *in,int len,unsigned char *out)
{
	char hx[16][5]={"0000","0001","0010","0011","0100","0101","0110","0111","1000","1001","1010","1011","1100","1101","1110","1111"};
	int j=0,i;
	
	for(i=0;i<len;i++)
		j+=sprintf(out+j,"%s",hx[conv(in[i])]);
	out[j]=0;
}


unsigned char tp_key[10][256]={
	"1a00e1b34817f3bac340eea1c25f7b7fd84f5534311bab42",
	"da9e056673ef01edb7dd4f00c614b8d4548e234c0764116d",
	"4d5948356e36390b3547129883badd12c8168fe5cec38356",
	"258bc6c00318ec2880c2d11138801ed52b2adbaac83c2782"};
unsigned char tp_iv[10][256]={
	"3fd09c2f438b596b7295b81c39f9a54b",
	"81d872f7dd7c9d6ecdeadd556965b433",
	"92de5d2999c1142a6a130ac55f1b7822",
	"b23e9f5eb270b3640f44b623c2a2805c"};
unsigned char inp[10][1024]={
	"033b3ea4d5055a212ecec7c1d09c8263b5d36e29ff58ecc432f7acf2a102c344263bfd2516f4741874756141659e3327e4cedeb8b703768ea242fc70da39781cbc234743bfecb7d6a895d180fddb7674bb13ae684b593ce1b3e976b20acd53bf",
	"6211b0ffffe478206e65c8fac9d824096db571b2fea016d4ac9b5ba1b47b14ac29988442f4c97cfe1a90c3983d91bafe664940a601fcd42229eff9f526d8dfa534933f11861687058ba7370c704d8b85e6845af925343eac31e4f5725c2b07c40c68a913beb3e25c4b14ecfd6af2ddc7",
	"92d1e2f1eabd7f3fdc99105093f5c03f13d0573a1ff6497b5a8df279acea2060e7a9d2bfabfc3f8187431a1f60dd1514173ea490664203700bc17a6e2964e095ebb75ef96a7f75a4d14d42d3bf530163ec77d18610a6b6ba006be4fc1ac03b38e4240e05f0ed288f03e011d475ff8d14dba26682e4c96b4081b1b98a49a53932",
	"eb493dab3317272f1f26bb6eb1c716e305f263d8cce4f32dfc0c9155c6280fa1c9ac25c185637c88125805ef11f78f5de47099251a5c64502da34d9e709d5ac74377130689d993d85cc5de02ffc375d1133b28a50e222cb1ead86dfc1a5125abc274ae8327c095aa6535efad6072f0c7fc1bb961917d72d599759977ac8d99d6af699f3f4862a9839470e0fa1d4d27c8"};

unsigned char exp_out[10][1024]={
	"0fa7c51b3884b5d734d56955078019b1822c66cb5779d351ada319f6799620d4fc0d9518efb521529d91d1073fb4b9aef62044219c62e782384f4c357cb3c2062366d26c7b12d90358cabcd01b53cdf3aff91b40f5ddb04d5ecc501c59ffe48c",
	"55544a5ba81fe6b91d9d76b47c9bc80524f49d98678d8918e6554e516af56606e11c87c1269de64fdd8b66e071f3bee70170929ca2f9d5e4a4f4652b17bb0203ea8d14df80344f725ae4f5f7c05eaa0000ba0881942cd92a5fcc427e6ea659e8ac70883e3ea749154cd56755b5b6e33f",
	"56cd225b88757a1b520d6ac236231b5d86d27d15a9b7769b71512ae922669abfe873de30ea7ecfc59c3a86703daa1070dc6e548efbdb972ce78191b4b173d46cdf67032bf515ed28bbfbc44a6d39df2882caffe6de76bccab49f765fa2dac8c548eb0ed57f03c49b8963b4a968e14164ffcf015e21a92c98497691a35d91146e",
	"8aa908ff06ef0de732eee5eeafc4be32ab9c23cd4ee6205b7f29e49c50d8b6677241c0fbbb6232454986dde2728c62abcbb47d2be912149f73733cb7e65b68e57bb2145aa45ce957c9037d099502d3b2d46ac3f848499267ad850058aef65566843ee119c483ccf8cc2a72c93467b0afdafd87b9843119c4859d5d428e2d371a54177fea6e4fdde8901191b713b60970"};

unsigned char ciphertext[1024];
unsigned char out[1024];

unsigned char outbin[5000];



int main (void)
{
	int no_of_samples = 4;
	int i,j,k,l;
	unsigned char key[256],iv[128],plaintext[1024];
	
	for(i=0;i<no_of_samples;i++)
	{		
		printf("SET %d\n",i+1);

		
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
		
//		printf("%d  %d\n",pt_len,strlen(inp[i]));
		//~ hex_to_bin(inp[i],strlen(inp[i]),inbin);
		hex_to_bin(out,strlen(out),outbin);
		
		printf("\nCiphertext in binary - \n%s\n\n",outbin);
		
		//~ strcpy(outbin,"1110001100010001010011101111001001001001111000110001000101001110111100100100100111100011000100010100111011110010010010011110001100010001010011101111001001001001");
		
		int n = strlen(outbin);
		int n0=0,n1=0,n00=0,n01=0,n10=0,n11=0;
		int cou3[8]={0};
		int cou4[16]={0};
		
		for(j=0;j<n;j++)
		{
			if(outbin[j]=='0')
				n0++;
			else
				n1++;
		}

		for(j=0;j<n-1;j++)
		{
			if(outbin[j]=='0' && outbin[j+1]=='0')
				n00++;
			else if(outbin[j]=='0' && outbin[j+1]=='1')
				n01++;
			else if(outbin[j]=='1' && outbin[j+1]=='0')
				n10++;
			else if(outbin[j]=='1' && outbin[j+1]=='1')
				n11++;
		}
		
		for(j=0;j<n-2;j+=3)
		{
			char tp[3]={0};
			strncpy(tp,outbin+j,3);
			int d1 = tp[0]=='0'?0:1;
			int d2 = tp[1]=='0'?0:1;
			int d3 = tp[2]=='0'?0:1;
			int num = d1*4 + d2*2 + d3;
			cou3[num]++;
		}
		
//		printf("%d\n%d %d\n%d %d %d %d\n",n,n0,n1,n00,n01,n10,n11);
		
		double X1 = ((double)((n0-n1)*(n0-n1)))/n;
		
		int y1 = (n00*n00) + (n01*n01) + (n10*n10) + (n11*n11);
		int y2 = (n0*n0) + (n1*n1);
		double X2 = ((4*(double)y1)/(n-1)) - ((2*(double)y2)/n) + 1 ;
		
		//~ for(j=0;j<8;j++)
			//~ printf("%d ",cou3[j]);
		//~ printf("\n\n");
		
		double y3=0.0;
		for(j=0;j<8;j++)
			y3 = y3 + (double)(cou3[j]*cou3[j]);
		int y4 = n/3;
		double X3 = ((y3 * 8)/y4) - y4;
		
		//~ ////// alpha = 0.05
		//~ double expX1 = 3.8415;
		//~ double expX2 = 5.9915;
		//~ double expX3 = 14.0671;
		
		//~ ////// alpha = 0.025
		//~ double expX1 = 5.0239;
		//~ double expX2 = 7.3778;
		//~ double expX3 = 16.0128;
		
		////// alpha = 0.01
		double expX1 = 6.6349;
		double expX2 = 9.2103;
		double expX3 = 18.4753;


		
		printf("Frequency Test\nX1 = %f    Threshold = %f ----- ",X1,expX1);
		if(X1<expX1)
			printf("Pass\n\n");
		else
			printf("Fail\n\n");
		
		printf("Serial Test\nX2 = %f    Threshold = %f  ----- ",X2,expX2);
		if(X2<expX2)
			printf("Pass\n\n");
		else
			printf("Fail\n\n");
		
		printf("Poker Test\nX3 = %f    Threshold = %f  ----- ",X3,expX3);
		if(X3<expX3)
			printf("Pass\n\n");
		else
			printf("Fail\n\n");
		
		
		printf("\n\n");
		
		/* Clean up */
		EVP_cleanup();
		ERR_free_strings();
		
	}

  return 0;
}
