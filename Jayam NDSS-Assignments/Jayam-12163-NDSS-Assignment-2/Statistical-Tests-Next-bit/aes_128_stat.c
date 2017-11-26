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
	"da52c0e4609e82ee926174a9eaf90b08",
	"56d6f7e2a870b92d55ff8d6e9c554d2a",
	"09f216ff78dfe419dfcef1a855473414",
	"cde9b69eea2b6a5588457e35e0a08803"};
unsigned char tp_iv[10][256]={
	"f2d0c5e86b4ddb40d30713aaa5a153fe",
	"b512f0e11e27fd1a94aa0c697bb6da5e",
	"722174c892d265291982c6f042ced145",
	"52323b54d69a62fec0689baee1b3ec63"};
unsigned char inp[10][1024]={
	"91d6c95a614cf85de16eeabe5976c2a2a9d307042f79a7aaeb7c3c57e1dd8d43bfa458c8c02e4f5ed0c960c9f17e3991dd2e0cb3ede18f96395a484001ef07ca4c97b411ce454aaf0f74242aca03786a93442171bd50a1467b9d663245d24c2f",
	"e62cdeac43667749701314c546f778a4c758e4f55760e7d729c3783cf7a242edf6ae3fcf0990886434896c945455bfae0e5674aa06ee6fb1512d94df2cac2447eeb849373bb3efbe7bb8d66c8a7ee559b17fc268d6599fcdef7457cdbde5b9c5b692236e4397545f2be97bd44f3993ad",
	"11f435e7e3656fcfa8e0df230311ca21054e84e13c8590e7ec7309f59c174022d467a7302641ee1b6ba46bee4f20bfda108bb78982f670b057dfbfe49da9cfae88490ce17241402b20d2fceb476d3a424e6c406d56ffc85278695d584d6c087cb4012ca2cf4daf284fd15ac1f2e183814957e934bf88dff4d777adfbb54933b5",
	"967798995af6f435b3a6f92bff77a11fa44d1426ae0f6e7dbafac27b123c5fc419be52c0ea412c4b3cac05ae89a4c0ce6f5e91a456b1bded5370a1234cf6f6ab5d0253507bc6f3f0573ab97585b67107dec059812323e021e341ad839ea9e3d02aeca43356add48ccef81f693ed53d32ba1c74a35e8a5f7f3115ef834f7daf9948244c4fc31f5487678d3e70fb27abb5"};

unsigned char exp_out[10][1024]={
	"416ae1e3d8350e7c291ef419c5e3465b388ee2d2f0014c04a5977e5617a00dfbeba7743155720fd646bbe64d8bbfd08817c4c4e97c1134574bc3829297655c08e39de77951d3996a1700a26bdc4292d3ce5c4294feab7619007bf3bd031bc763",
	"3abae717e8370f53c3ee5571739dce8a611bb51538569fdd17f3c011642cd78111dc9520f9d357351ffb8ab77b38bb5c34f2dd02e497ff876887f2a3b26fbfcab7955817780fca751b9ef74eedd38ee0ab4bc1ece453e6765916d345e1bdbd42ad6d508c5ff375df20fc8948b6310f2d",
	"e0e518e2d339b2e878937cd44d4e5bac40315eb226949a8b0e5863d9e543bc09936440c654764f03e5adab5b76b61218492e9f0e4578de990f1a486506c26eea4a3ea9682946ae4a462f90482a2cff19ac7846587dae80a3f1d3408583d065594869b00ddd17ae19d8e09d8d31eb7f7579320c9f26467ff0c58c86f22a3a217e",
	"6a5747276037643bbd0013c265d8d9a80b0299b283514d5256fecb5c787002a291a18a765fa046c3243418b02eebfc0c599576e52dd8c30291c97ceaa8bd2d7dbee3e66db7b585ea2b67f46f6711df28456b801556e233a96da1a8c34cd4d6154b20f43ae27b8ae83d907f9355c87aa021a280232265e99b4e189f4a3ccaa6b5e04153961e8e427a2dd53e5ec6f5112a"};

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
