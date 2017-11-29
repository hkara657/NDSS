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

#define BigPair pair<BigInt,BigInt>
#define zero Integer(0)
#define one Integer(1)

BigPair G = make_pair( Integer("602046282375688656758213480587526111916698976636884684818"), Integer("174050332293622031404857552280219410364023488927386650641") );
BigInt MOD = Integer("6277101735386680763835789423207666416083908700390324961279"); // or p
BigInt a = MOD-Integer("3");  // a is -3, but since we cannot represent -ve in bigint we do it -3
//~ BigInt b = Integer("2455155546008943817740293915197451784769108058161191238065");
//~ BigInt n = Integer("6277101735386680763835789423176059013767194773182842284081");

BigInt inf = Integer("100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");  // just to represent infinity
BigPair ecc_INF = make_pair(inf,inf);


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
	char *msg=(char *)malloc(1024*sizeof(char));
	read( socket_id , msg, 1024);
	return msg;
}

int main(int argc, char const *argv[])
{
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
	
	send_message( convert_to_char_pointer(A) );  //sending A
	BigInt B = Integer( get_message()  );  // receiving B
	
	
	
	
	
	BigInt final_key = modpow(B, a, p);
	cout<<"key with Alice is    ";	cout<<final_key;	EL;
	
	
    return 0;
}
