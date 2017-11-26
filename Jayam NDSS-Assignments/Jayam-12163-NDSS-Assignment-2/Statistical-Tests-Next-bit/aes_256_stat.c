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
	"1d5d440ee1c72740f7bbea5db587b0c5834344f091b4666ac571631bf844e9cc",
	"686bda53073e94d8a8113ac291a0eec18534258445184dcf564db4ce057ea5a9",
	"a0bf10c0b4fd2552d26ac9e9c2bf9a3ea7a37d352633df11cae241e4a783f34a",
	"108a06c812f2cacb5e521acad0eac6a6db32fa2e1d1b6d883798dad3db5db40a"};
unsigned char tp_iv[10][256]={
	"1088128efc7d4cdc629d3874c727aa2c",
	"f0cd1d670c031bca0dc1d6f4b39d1fc8",
	"20db833498b37dfc5866c732ba7a22a4",
	"baadd9b9a14280d4610d41685c36b778"};
unsigned char inp[10][1024]={
	"e8e8ed02c13b9852274cdc60a9fe5e52a9bb2f056069f1a223993c72e40140f3fb2cab2b2770cd3ccf21f9398e042f38ef06f9a8752e93e5dfd14e0aa9053607d657f3f3edc1eda342d6b47b76409e84416cb2bf6f84c4b9299ee2607633ef15",
	"5d20b4d0a2ac43cbf8120fa9da387915d7c0ab62872d2cccc347b10115c037e06e174e8017bdb874ea77324dc203926130fe12cb7005ecb39b1b27d01d4ab02a6a8dac25edee0dbb41ec6309a41ff50da91f11ae2da1a0fc8be3fdba144b081ab94b76c70b876b28663a4ae468d5cca1",
	"27af4a135b4c0f33ec03e5ffe351a9edac7ada8f62c3fe684ee241feaab36030aa2cc5cabd93f45710ee253653bc32f0c1e2b4c95ae869957365dacd71b83ae2d2f990d16d3019f8fac4e728d436cffbfe0e82686416fa9464c718eb8d018b70a7fff351f38946bfb46b73fced2746b66de78c9309b5770d29ee448086f41a81",
	"d57fb32d6ec9d3190c14c5015281fe1bf5056935d904acec7722ac1f825653a3ca40913860bca0bcfbb78d9f9a41f4976be40b95ec34e1f750a8e8ff24a8b28432e7f8e7a6f3e0496f0b7ffbe8309d36b87eb90df7bd4d9f92345491f0bd08bcd51ff02287971a2730b8a6fe84768461a37d7d8541c7784d046df6be2dbde0b37b8e82d14cd0d7be0667078eb53a2e7e"};

unsigned char exp_out[10][1024]={
	"a862293bda833a8ad5f1875d1ebf5e5d250203a5ac2f6c0f029f2c515a8a731018626806820647ad088a29fd3b4e92b05f47d5651e3767869c9d289010c7926ad8d64c98f2a7544eddae2522327371039cf757c6591649b3b59b4e5a84b5a7b2",
	"d2ddf06ce095f6142c2c929cac8ff63c47832d474bf5160b5e7142aa68b9c2736b6f1a49395a525f06ca56df5f7941ac39a7048d891ccca10e6a14779451a740b4854cb872b4b36e9984a7fb9d03dee8c26b2d7a23e377a36ab35b6d9a26fb397b03200cf1c6987f6da0924d7181e003",
	"0621f4800b001c44ee3e3ea4ca70248bfd01a8045b6ca46047f9b91b22e70bb04e6e4bd2dc5759112967cf7dcbf6d6134681adf1226f51c69fdef9f191575157ac688e9908d7e4aae31fe573072ee1366f64a8f118d798e6f7d2d862904fa445158d2e97d4d38cd804f9f207f11a6fca24e46485ec86b5e970998aa6fd552319",
	"f2d8aacd5179584d68bedd301ddb1c0b8e6e0b02d0985944c59bf8bf8a7299b69518bb761c26af7da204ac2fed069271a0afb177c3fc880428c07eabb0e151164371ee1fc5d1f9d8e1321d8b3d73881ea968674ad5950c2c7fe6dd4773ffdfb3970a65db8e33787f24dbed8947f1644bc6b8a79a2b19428589fb8b1337257ba53a6a68fc2b2160e077a307e0a7ebc3bc"};

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
