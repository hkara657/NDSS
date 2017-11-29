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

#define BigPair pair<BigInt,BigInt>
#define zero Integer(0)
#define one Integer(1)
BigInt inf = Integer("100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");  // just to represent infinity
BigPair ecc_INF = make_pair(inf,inf);

BigPair G=make_pair(zero,zero);
BigInt MOD,a,b,n;
//-----------------------------a = MOD-Integer("3");  // a is -3, but since we cannot represent -ve in bigint


int num_bits=128;
int socket_id = 0;
void printPair(BigPair P);
void initialize_ecc_group(string filename)
{
	ifstream fin(filename);
	
	string inp[6];
	int i=0;
	
	string line;
	while( std::getline( fin, line ) ) // for each line read from the file
	{
		inp[i]=line;
		i++;
	}
	
    G.X=Integer(inp[0]);
    G.Y=Integer(inp[1]);
    MOD=Integer(inp[2]);
    
    if(inp[3][0]!='-')
		a = Integer(inp[3]);
	else
		a = MOD-Integer(inp[3].substr(1));  // bcz we can't represent -ve numbers in BigINt datatype
		
    b= (inp[4][0]=='-'? MOD-Integer(inp[4].substr(1)) : Integer(inp[4]) );//not needed, here also handle -ve case
    n=Integer(inp[5]);//not needed
}
//--------------------------------------------ecc part starts
void printPair(BigPair P)
{
	cout<<"The point is \n";
	cout<<"X cordinate is ";cout<<P.X;
	EL;
	cout<<"Y cordinate is ";cout<<P.Y;
	EL;
}
BigPair ecc_add_util( BigPair P, BigPair Q, BigInt m)
{
	BigPair ans = make_pair(zero,zero);
	//~ ans.X = m*m - (P.X + Q.X);
	//~ ans.Y = m*(P.X-ans.X) - P.Y;
	ans.X = ( (m*m) + 2*MOD - (P.X + Q.X) )%MOD;    //2*MOD is added because -ve BIGINT is not defined
	ans.Y = ( m*(P.X + MOD - ans.X) + MOD - P.Y )%MOD;
	return ans;
}

BigPair point_double(BigPair P)
{
	if(P.Y==0) // in point doubling if Y cordinate is 0 then point doubling is INFINITY
	return ecc_INF;
	
	//~ BigInt m = (3*P.X*P.X + a) / (2*P.Y);
	BigInt m = ( (3*P.X*P.X + a) * modpow( (2*P.Y), MOD-2, MOD )  )%MOD;
	return ecc_add_util(P, P, m);	
}

BigPair ecc_add(BigPair P, BigPair Q)
{
	//checking if same points
	if(P.X==Q.X && P.Y==Q.Y)
	return point_double(P);
	
	//checking if vertical points i.e. points not equal but are vertically aligned i.e. same x cordinate, then addition answer is INIFNITY
	if(P.X==Q.X)
	return ecc_INF;
	
	//zero element added with x gives x. here P is zero element so answer is Q
	if(P.X==inf)
	return Q;
	
	if(Q.X==inf)
	return P;
	
	//~ BigInt m = (Q.Y-P.Y) / (Q.X-P.X);
	BigInt m = ( (Q.Y + MOD - P.Y) * modpow( (Q.X + MOD -P.X), MOD-2, MOD )  )%MOD;
	return ecc_add_util(P, Q, m);	
}

BigPair ecc_mult(BigPair P, BigInt k)
{
	if(k==0)
	return ecc_INF;
	
	if(k==one)
	return P;
	
	BigPair ans = ecc_mult(P, k/2);
	
	if( ans.X != inf )
	ans = point_double(ans) ;
	
	if(k%2 == 1)
	ans = ecc_add(ans, P) ;
	
	return ans;
}
//--------------------------------------------ecc part ends

//--------------------------------------------connection part starts

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
	char *msg=(char *)malloc(5024*sizeof(char));
	read( socket_id , msg, 5024);
	return msg;
}
//--------------------------------------------connection part ends


int main(int argc, char const *argv[])
{
	cout<<"BOB\n";
	srand(time(NULL));
    initialize_ecc_group("abc.txt");
    
	make_connection();
	
	
	cout<<"\a Connection Established Successfully \n";
	
	BigInt tb = random_primes(num_bits/2);  // secret key of Bob
	
	BigPair B = ecc_mult(G,tb);  // tb*G % MOD   sent by B to A
	cout<<"\a B computed is  ";	printPair(B);
	
	
	
	
	send_message( convert_to_char_pointer(B.X) );  //sending B
	cout<<"sent b.x";EL;
	
	BigPair A = make_pair(zero,zero);
	A.X = Integer( get_message() );  // receiving A
	cout<<"A.X is ";cout<<A.X; EL;
	
	send_message( convert_to_char_pointer(B.Y) );  //sending B
	cout<<"sent b.y";EL;
	
	A.Y = Integer( get_message() );  // receiving A
	cout<<"A.Y is ";cout<<A.Y;EL;
	
	
	
	
	BigPair final_key = ecc_mult(A,tb);
	cout<<"\a key with Bob is    ";	printPair(final_key);	EL;
	
    return 0;
}
