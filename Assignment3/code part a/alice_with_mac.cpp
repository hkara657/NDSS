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

int socket_id;
int num_bits=512;

void make_connection()
{
	int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    //~ char buffer[1024] = {0};
    //~ char *hello = (char *)"Hello from server";
      
    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
      
    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("10.192.32.14");
    //address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( PORT );
      
    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&address, 
                                 sizeof(address))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((socket_id = accept(server_fd, (struct sockaddr *)&address, 
                       (socklen_t*)&addrlen))<0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    //~ valread = read( socket_id , buffer, 1024);
    //~ printf("%s\n",buffer );
   
    //~ send(socket_id , hello , strlen(hello) , 0 );
    //~ printf("Hello message sent\n");
      
    //~ valread = read( socket_id , buffer, 1024);
    //~ printf("%s\n",buffer );
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
    cout<<"ALICE\n";
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

	
	BigInt a = random_primes(num_bits/2);  // secret key of Alice
	
	BigInt A = modpow(g, a, p);  // g^a mod p   sent by A to B
	
	//------------------------sending A
	//send_message( convert_to_char_pointer(A) );
	unsigned char *mac = get_mac(convert_to_unsigned_char(convert_to_char_pointer(A)));
	char *ax = _merge(mac,convert_to_char_pointer(A));
	send_message( ax );  //sending mac(A) || A
	
	
	//------------------------ receiving B
	//BigInt B = Integer( get_message()  ); 
	char *tmp = get_message();    // receiving B
	if(check_mac( convert_to_unsigned_char(tmp) ))
	cout<<"MAC Correct for B\n";
	else
	{cout<<"MAC wrong for B"; exit(0);	}
	
	BigInt B = Integer( &tmp[16] );
	
	
	
	BigInt final_key = modpow(B, a, p);
	cout<<"key with Alice is    ";	cout<<final_key;	EL;
    return 0;
}
