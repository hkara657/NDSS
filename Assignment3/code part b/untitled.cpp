#include <stdio.h>
#include <openssl/cmac.h>
#include <iostream>
#include <string.h>
using namespace std;

unsigned char key[] = { 0x2b,0x7e,0x15,0x16, 
                          0x28,0xae,0xd2,0xa6,
                          0xab,0xf7,0x15,0x88,
                          0x09,0xcf,0x4f,0x3c};
                          
                          
void printBytes(unsigned char *buf, size_t len) {
  for(int i=0; i<len; i++) {
    printf("%02x ", buf[i]);
  }
  printf("\n");
}


unsigned char* convert_to_unsigned_char(char *msg)
{
	int len=strlen(msg);
	unsigned char *tmp = (unsigned char *)calloc(len+1,sizeof(unsigned char));
	for(int i=0;i<len;i++)
	{
	  tmp[i]=(unsigned char)msg[i];
	}
	return tmp;
}

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




int length(unsigned char* tmp)
{
	int i=0;
	while(tmp[i]!='\0')
	i++;
	return i;
}

unsigned char* _merge(unsigned char* mac, unsigned char* msg)
{
	int i,len=length(msg);
	unsigned char *tmp = (unsigned char *)calloc(20+len,sizeof(unsigned char));
	
	for(i=0;i<16;++i)
	{
		tmp[i]=mac[i];
	}
	
	for(i=0;i<len;++i)
	{
		tmp[i+16]=msg[i];
	}
	tmp[i+16]='\0';
	
	return tmp;
}

bool check_mac(unsigned char* msg)
{
	// if msg is char and not unsigned char then make it strlen
	
	//~ unsigned char *mac = (unsigned char *)calloc(16,sizeof(unsigned char));
	//~ for(i=0;i<16;++i)
	//~ mac[i]=msg[i];
	
	unsigned char *new_mac;
	
	cout<<"\n message in check is"<<&msg[16]<<"---"<<"\n\n";
	new_mac = get_mac( &msg[16] );  //first 16 bits is mac ans remaining is msg
	cout<<"\n !!!!!!!!!!new mac is ";printBytes(new_mac,16);cout<<"\n";
	
	cout<<"\n old mac is ";printBytes(msg,16);cout<<"\n";
	
	for(int i=0;i<16;++i)
	{
		if(new_mac[i]!=msg[i])
		return false;
	}
	
	return true;
}

int main(int argc, char *argv[])
{
  char msg[] = "997764822765";
  //~ cout<<strlen(msg)<<"\n";
  //~ cout<<length(convert_to_unsigned_char(msg));
  //cout<<sizeof(msg)<<"\n"<<(msg[3]==0);
  
	//printBytes(convert_to_unsigned_char(msg),strlen(msg));
	//cout<<"\n";
	cout<<"\n message before is"<<convert_to_unsigned_char(msg)<<"---"<<"\n\n";
	unsigned char* mac = get_mac( convert_to_unsigned_char(msg) );
	cout<<"!!!!!!!!old mac is ";printBytes(mac,16);cout<<"\n";
	
	mac = _merge(mac,convert_to_unsigned_char(msg));
	cout<<"in main\n";
	printBytes(mac,16);
	cout<<&mac[16];
	
	cout<<check_mac(mac);
}
