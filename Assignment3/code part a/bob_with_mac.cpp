// Client side C/C++ program to demonstrate Socket programming
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

int num_bits=512;
int socket_id = 0;

void make_connection()
{
	//~ struct sockaddr_in address;
    //~ int valread;
    struct sockaddr_in serv_addr;
    
    if ((socket_id = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        exit(EXIT_FAILURE);
    }
  
    memset(&serv_addr, '0', sizeof(serv_addr));
  
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    serv_addr.sin_addr.s_addr = inet_addr("10.192.32.14");
    
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "10.192.32.14", &serv_addr.sin_addr)<=0) 
    {
        printf("\nInvalid address/ Address not supported \n");
        exit(EXIT_FAILURE);
    }
  
    if (connect(socket_id, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed out\n");
        exit(EXIT_FAILURE);
    }
}

void send_message(char* msg)
{
	send(socket_id , msg , strlen(msg) , 0 );
}

char* get_message()
{
	char *msg=(char *)calloc(1024,sizeof(char));
	read( socket_id , msg, 1024);
	return msg;
}


// ---------------------------------------------------MAC starts

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
	int i,len=strlen(msg);
	unsigned char *tmp = (unsigned char *)calloc(len+1,sizeof(unsigned char));
	for(i=0;i<len;i++)
	{
	  tmp[i]=(unsigned char)msg[i];
	}
	tmp[i]='\0';
	return tmp;
}

int length(unsigned char* tmp)
{
	int i=0;
	while(tmp[i]!='\0')
	i++;
	return i;
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



char* _merge(unsigned char* mac, char* msg)
{
	int i,len=strlen(msg);
	char *tmp = (char *)calloc(20+len,sizeof(char));
	
	for(i=0;i<16;++i)
	{
		tmp[i] = (char)mac[i];
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
	unsigned char *new_mac;
	
	new_mac = get_mac( &msg[16] );  //first 16 bits is mac ans remaining is msg
	
	for(int i=0;i<16;++i)
	{
		if(new_mac[i]!=msg[i])
		return false;
	}
	
	return true;
}
//------------------------------------MAC ends

int main(int argc, char const *argv[])
{
    cout<<"BOB\n";
	srand(time(NULL));
	
	make_connection();
	cout<<"Connection Established Successfully \n";

	string s;
	ifstream in("prime.txt");
	in>>s;
	BigInt p = Integer(s);
	
	ifstream in2("generator.txt");
	in2>>s;
	BigInt g = Integer(s);
	
	
	BigInt b = random_primes(5 + num_bits/2);  // secret key of Bob
	
	BigInt B = modpow(g, b, p);  // g^b mod p   sent by B to A
	
	//send_message( convert_to_char_pointer(B) );  //sending B to Alice
	unsigned char *mac = get_mac(convert_to_unsigned_char(convert_to_char_pointer(B)));
	char *bx = _merge(mac,convert_to_char_pointer(B));
	send_message( bx );  //sending mac(B) || B
	
	
	//BigInt A = Integer( get_message()  );  // receiving A from Alice
	char *tmp = get_message();    // receiving A
	if(check_mac( convert_to_unsigned_char(tmp) ))
	cout<<"MAC Correct for A\n";
	else
	{cout<<"MAC wrong for A"; exit(0);	}
	
	BigInt A = Integer( &tmp[16] );
	
	
	
	BigInt final_key = modpow(A, b, p);
	cout<<"key with Bob is    ";	cout<<final_key;	EL;
    return 0;
}
