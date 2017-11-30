// Server side C/C++ program to demonstrate Socket programming
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#define PORT 8095
#include<sys/unistd.h>
#include<arpa/inet.h>
#include "GeneratePrime.cpp"
#include <fstream>
#include <openssl/cmac.h>

#define BigPair pair<BigInt,BigInt>
#define zero Integer(0)
#define one Integer(1)
//~ BigInt inf = Integer("100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");  // just to represent infinity
//~ BigPair ecc_INF = make_pair(inf,inf);

BigPair G=make_pair(zero,zero);
BigInt MOD,a,b,n;
//-----------------------------a = MOD-Integer("3");  // a is -3, but since we cannot represent -ve in bigint

int num_bits=128;
int socket_id;

void printBytes(unsigned char *buf, size_t len) {
  for(int i=0; i<len; i++) {
    printf("%02x ", buf[i]);
  }
  printf("\n");
}

//~ int cmac_compute(unsigned char inp[], int inplen, char macout[])
//~ { 
	//~ unsigned char mact[20]={0};
  //~ size_t mactlen;
  //~ CMAC_CTX *ctx = CMAC_CTX_new();
  //~ CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL); 
  //~ CMAC_Update(ctx, inp, inplen);
  //~ CMAC_Final(ctx, mact, &mactlen);
  
  //~ int i,j;
  //~ unsigned char cur;
  //~ for(i=0;i<mactlen;i++)
  //~ {
	//~ cur = mact[i];
	//~ for(j=0;j<8;j++)
	//~ {
		//~ macout[i*8+j] = (cur%2)+'0';
		//~ cur=cur/2;
	//~ }
  //~ }
  
  //~ return (i*8);
//~ }

int main()
{
	unsigned char mact[16] = {0};  	
	size_t mactlen;

	unsigned char key[] = { 0x2b,0x7e,0x15,0x16, 
                          0x28,0xae,0xd2,0xa6,
                          0xab,0xf7,0x15,0x88,
                          0x09,0xcf,0x4f,0x3c};
  // M: 6bc1bee2 2e409f96 e93d7e11 7393172a Mlen: 128
  unsigned char message[] = { 0x6b,0xc1,0xbe,0xe2, 
                              0x2e,0x40,0x9f,0x96, 
                              0xe9,0x3d,0x7e,0x11, 
                              0x73,0x93,0x17,0x2a };
	//~ cout<<message;
	//~ return 0;
	CMAC_CTX *ctx = CMAC_CTX_new();
	
	//~ CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL);

	//~ CMAC_Update(ctx, message, sizeof(message));

	//~ CMAC_Final(ctx, mact, &mactlen);
//~ cout<<"llll";
	//~ cout<<mact;
	//printBytes(mact, mactlen);
cout<<"eeeeee";  
return 0;
}
