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
	
	
	BigInt b = random_primes(5 + num_bits/2);  // secret key of Bob
	
	BigInt B = modpow(g, b, p);  // g^b mod p   sent by B to A
	
	send_message( convert_to_char_pointer(B) );  //sending B to Alice
	
	BigInt A = Integer( get_message()  );  // receiving A from Alice
	
	BigInt final_key = modpow(A, b, p);
	cout<<"key with Bob is    ";	cout<<final_key;	EL;
    return 0;
}
