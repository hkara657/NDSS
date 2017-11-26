///////////////////////////////////////////////////////////////
/////      Authenticated Diffie Hellman Key Exchange     //////
///////////////////////////////////////////////////////////////


#include <bits/stdc++.h>
#include "BigInteger.cpp"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <openssl/cmac.h>
#include <openssl/sha.h>

using namespace std;


int n_bits = 512;


////// my own exponentiation function 
BigInt modpow(BigInt a, BigInt b, BigInt mod) {
	string one="1";
	BigInt ans = Integer(one);
	a%=mod;
	while(b>0)
	{
		if(b%2==1)
		{
			ans*=a;
			ans%=mod;
		}
		a*=a;
		a%=mod;
		b/=2;
	}
	return ans;
}

BigInt genrand(int bits)
{
	int i,k;
	BigInt n = Integer(0);
	for(i=0;i<bits;i++)
	{
		k=rand()%2;
		n = (n * 2) + k;
	}
	return n;
}

BigInt one = Integer(1);
BigInt zero = Integer(0);
BigInt two = Integer(2);


BigInt randzp(BigInt p,int max_bits)
{
	BigInt g;
	do
	{
		BigInt rand1 = genrand(max_bits);
		BigInt rand2 = genrand(max_bits);
		g = rand1 * rand2;
		g = g % p;
	}while(g==one || g==zero);
	return g;
}

void bigtostr(BigInt num,char str[],int max_bits)
{
	int i;
	BigInt rem;
	for(i=0;i<max_bits;i++)
	{
		rem = num % two;
		if(rem==zero)
			str[i]='0';
		else
			str[i] = '1';
		num = num/2;
	}
}

BigInt strtobig(char str[],int here_bits)
{
	int i;
	BigInt num = Integer(0);
		
	for(i=here_bits-1;i>=0;i--)
	{
		num = num * 2;
		if(str[i]=='1')
			num = num + 1;
	}
	return num;
}

int strtounsch(char str[], int here_bits, unsigned char outp[])
{
	int i,j;
	int num;
	for(i=0;i<here_bits; i+= 8)
	{
		num=0;
		for(j=i;j<(i+8);j++)
			num = num*2 + (str[j]-'0');
		outp[i/8] = (unsigned char)num;
	}
	return (here_bits/8);
}

unsigned char key[] = { 0x2b,0x7e,0x15,0x16, 
                          0x28,0xae,0xd2,0xa6,
                          0xab,0xf7,0x15,0x88,
                          0x09,0xcf,0x4f,0x3c};

int cmac_compute(unsigned char inp[], int inplen, char macout[])
{ 
	unsigned char mact[20]={0};
  size_t mactlen;
  CMAC_CTX *ctx = CMAC_CTX_new();
  CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL); 
  CMAC_Update(ctx, inp, inplen);
  CMAC_Final(ctx, mact, &mactlen);
  
  int i,j;
  unsigned char cur;
  for(i=0;i<mactlen;i++)
  {
	cur = mact[i];
	for(j=0;j<8;j++)
	{
		macout[i*8+j] = (cur%2)+'0';
		cur=cur/2;
	}
  }
  
  return (i*8);
}

int sha256(char *string, int len, char outp[])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, len);
    SHA256_Final(hash, &sha256);
    int i,j;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
		unsigned char cur=hash[i];
		for(j=0;j<8;j++)
		{
			outp[i*8+j] = (cur%2) + '0';
			cur=cur/2;
		}
    }
    return (i*8);
}

int main(int argc, char *argv[])
{
	srand(time(NULL));
	int i,j,k,l,n,m,ch,count=0,no_gen=0;
	double total_time_1=0,total_time_2=0;

	int rand_bit_lim = 512;
	int p_bits = 512;


	double time_spent;
	double total_time=0.0;
	clock_t begin,end;
	
	
	cout<<"Generating public parameters - \n\n";
	
	begin = clock();
	
	string pri = "11394884647602561200739195439210799667827406275129711954880070420859840417872988165182257949052349866437867857014785512379989629646924405020239723585249547";	
	BigInt p = Integer(pri);  ///// prime for Zp
	BigInt q = (p-1)/2;
	BigInt g,beta;
	do
	{
		g = randzp(p,rand_bit_lim);
		beta = modpow(g, q, p);
	}while(beta!=one);
	
	end = clock();
	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	total_time += time_spent;
	
	
	cout<<"p is ";
	cout<<p;
	cout<<endl;

	cout<<"g is ";
	cout<<g;
	cout<<endl;
	
	int listenfd,connfd;
	struct sockaddr_in serv_addr;
	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&serv_addr, '0', sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;    
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
	serv_addr.sin_port = htons(atoi(argv[1]));
		
	bind(listenfd, (struct sockaddr*)&serv_addr,sizeof(serv_addr));

	if(listen(listenfd, 1024) == -1 )
		{
		printf("Failed to listen\n");
		return -1;
		}
	
	char pBuff[1024]={0};
	char gBuff[1024]={0};
	char gxBuff[1024]={0};
	char gyBuff[1024]={0};
	char gxyBuff[1024]={0};
	
	cout<<"Now start other party\n\nWaiting for other party to connect .... \n\n";
	
	connfd = accept(listenfd, (struct sockaddr*)NULL ,NULL);


	bigtostr(p,pBuff,p_bits);
	write(connfd,pBuff,strlen(pBuff));
	sleep(2);
	
	bigtostr(g,gBuff,p_bits);
	write(connfd,gBuff,strlen(gBuff));	


/////// choose x and send g^x 	
	begin = clock();

	BigInt x = randzp(p,rand_bit_lim);
	BigInt gx = modpow(g, x, p);
	
	cout<<"x is ";
	cout<<x;
	cout<<"g^x is ";
	cout<<gx;
	cout<<endl;
	
	unsigned char gxmacinp[1024]={0};
	char gxmac[1024] = {0};
	bigtostr(gx,gxBuff,p_bits);
	int gxinplen = strtounsch(gxBuff,p_bits,gxmacinp);
	int gxmaclen = cmac_compute(gxmacinp,gxinplen,gxmac);

	end = clock();

	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	total_time += time_spent;
	
	cout<<"MAC(g^x) is \n";
	cout<<gxmac<<endl;
	
	strcpy(gxBuff+p_bits,gxmac);
	write(connfd,gxBuff,strlen(gxBuff));
	
///// receive g^y	
	n=read(connfd,gyBuff,1024);

	begin = clock();

	char macbuff[150] = {0};
	for(i=p_bits; i<(p_bits+128);i++)
		macbuff[i-p_bits] = gyBuff[i];	
	gyBuff[p_bits]=0;
	
	BigInt gy = strtobig(gyBuff,p_bits);
	cout<<"\ng^y received is ";
	cout<<gy;
	cout<<endl;
	cout<<"MAC(g^y) received is \n"<<macbuff<<endl<<endl;

	unsigned char gymacinp[1024]={0};
	char gymac[1024] = {0};	
	int gyinplen = strtounsch(gyBuff,p_bits,gymacinp);
	int gymaclen = cmac_compute(gymacinp,gyinplen,gymac);
	
	cout<<"MAC(g^y) computed is \n"<<gymac<<endl<<endl;
	
	for(i=0;i<128;i++)
	{
		if(macbuff[i]!=gymac[i])
			break;
	}
	if(i!=128)
	{
		cout<<"Error : MAC does not match\n\n";
		return 0;
	}
	else
		cout<<"MAC verified\n\n";	
	



	BigInt gyx = modpow(gy, x, p);
	cout<<"(g^y)^x is ";
	cout<<gyx;
	cout<<endl;
	
	char final_key[1024]={0};
	
	bigtostr(gyx,gxyBuff,p_bits);
	int key_len = sha256(gxyBuff,p_bits,final_key);
	final_key[128]=0;  ///// truncate output to 128 bits
	
	cout<<"\n\nFinal 128-bit key is - \n"<<final_key<<"\n\n";
	
	end = clock();
	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	total_time += time_spent;

	cout<<"Time taken to compute keys (excluding network delay) = "<<total_time<<" seconds\n\n";
	
	
	
    return 0;
}
