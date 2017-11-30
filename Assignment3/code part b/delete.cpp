//~ #include <stdio.h>
//~ #include <openssl/cmac.h>
#include<bits/stdc++.h>
using namespace std;
//~ void printBytes(unsigned char *buf, size_t len) {
  //~ for(int i=0; i<len; i++) {
    //~ printf("%02x ", buf[i]);
  //~ }
  //~ printf("\n");
//~ }
//~ unsigned char key[]="mynameisharshka";
unsigned char* get_mac(unsigned char* message)
{
	
	unsigned char *mact = (unsigned char *)calloc(16,sizeof(unsigned char));
  size_t mactlen;

  CMAC_CTX *ctx = CMAC_CTX_new();
  CMAC_Init(ctx, key, sizeof(key), EVP_aes_128_cbc(), NULL); 
  CMAC_Update(ctx, message, sizeof(message));
  CMAC_Final(ctx, mact, &mactlen);
	CMAC_CTX_free(ctx);
	return mact;
}
int main()
{

  char message[] = "harsh";
  int mlen=strlen(message);
  cout<<mlen<<"\n";
  
  unsigned char nm[100]={0};
 
  for(int i=0;i<strlen(message);i++)
  {
	  nm[i]=(unsigned char)message[i];
  }
  
  //~ printf("%d\n",sizeof(message));

  //~ unsigned char* mac = get_mac(message);
  //~ printf("%d\n",sizeof(mac));
  //~ printBytes(mac, 16);
 

  
  return 0;
}

