#include<bits/stdc++.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
using namespace std;


int length(unsigned char* tmp)
{
	int i=0;
	while(tmp[i]!='\0')
	i++;
	return i;
}

//* *****************************    AES starts
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

	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
	handleErrors();

	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
	handleErrors();
	ciphertext_len = len;

	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);
	cout<<length(ciphertext)<<"\n";;
	return ciphertext_len;
}
//* *****************************    AES ends

void xor_msg(char *ans, char *tmp, int l)
{
	int i=0;
	for(i=0;i<l;++i)
	ans[i]=ans[i]^tmp[i];
}

int main()
{
	unsigned char *key = (unsigned char *)"0123456789012345678901234567890155580909";
	unsigned char *iv = (unsigned char *)"0123456789012345678901234567890155580909\0";
	unsigned char *inp = (unsigned char *)"0123456789012345";
	
	unsigned char *plaintext = (unsigned char *)"The quick brown fox\0";
	cout<<length(plaintext)<<"\n";
	unsigned char ciphertext[1000]={0};
	int ciphertext_len;
	
	ciphertext_len = encrypt (inp, strlen ((char *)inp)-1, key, iv,ciphertext);
	unsigned char ciphertext2[128]={0};
    ciphertext_len = encrypt (ciphertext, strlen ((char *)ciphertext)-1, key, iv,ciphertext2);
    unsigned char ciphertext3[128]={0};
    ciphertext_len = encrypt (ciphertext2, strlen ((char *)ciphertext2)-1, key, iv,ciphertext3);
    
    
    //~ std::cout << "a = " << typeid(std::bitset<8>(5)).name()  << std::endl;
    //~ std::cout << "a = " << std::bitset<16>(511)  << std::endl;
    //cout<<ciphertext_len<<"\n";
    //~ int i=0;
    //~ while(ciphertext[i] && i<5)
    //~ {
		//~ int n=(int)ciphertext[i];
		//~ cout<<std::hex<<n<<"\n"<<std::bitset<16>(n)<<"\n"<<std::bitset<16>(n^(511))<<"\n#####\n";
		//~ i++;
	//~ }
	

}
