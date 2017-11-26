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

#pragma pack(1)
struct csr
{
	char name[50];
	char mobile[20];
	char email[50];
	char aadhar[15];
	char pub_key_str[520];
	int key_type;  /////// 0 if DH is used and 1 is RSA is used
	char pr[520];				///// public key
	char gen[520];			///////// parameters
	char hash_fun[15];
};
#pragma pack(0)

#pragma pack(1)
struct enc
{
	char grstr[520];
	char gxrmstr[520];
};
#pragma pack(0)

#pragma pack(1)
struct certificate
{
	char name[50];
	char mobile[20];
	char email[50];
	char aadhar[15];
	char pub_key_str[520];
	int key_type;  /////// 0 if DH is used and 1 is RSA is used
	char pr[520];				///// public key
	char gen[520];			///////// parameters
	char hash_fun[15];
	int expire_time;
	char sign1[520];
	char sign2[520];
};
#pragma pack(0)

#pragma pack(1)
struct new_cert
{
	char pub_key_str[520];
	char sign1[520];
	char sign2[520];
};
#pragma pack(0)

struct new_cert b_cert,c_cert;

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

BigInt randzp1(BigInt p,int max_bits)
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

void print_csr(struct csr b_csr)
{
	printf("Certificate Signing Request - \n");
	printf("Name          -   %s\n",b_csr.name);
	printf("Mobile        -   %s\n",b_csr.mobile);
	printf("Email         -   %s\n",b_csr.email);
	printf("Aadhar        -   %s\n",b_csr.aadhar);
	printf("Key type      -   %d\n",b_csr.key_type);
	printf("Hash Function -   %s\n",b_csr.hash_fun);
	
	BigInt pub_key = strtobig(b_csr.pub_key_str,512);
	printf("\nPublic key - ");	
	cout<<pub_key;
	cout<<endl;
	
	BigInt p = strtobig(b_csr.pr,512);
	BigInt g = strtobig(b_csr.gen,512);

	printf("Public key Parameters\np - ");
	cout<<p;
	cout<<endl;
	printf("g - ");
	cout<<g;
	cout<<endl;
	printf("******** CSR end **********\n\n");

}



BigInt sha512(char *string, int len)
{
	unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, string, len);
    SHA512_Final(hash, &sha512);
    
    BigInt ans = zero;
    
	int i,j;
    for(i = 0; i < SHA512_DIGEST_LENGTH; i++)
    {
		int cur = int(hash[i]);
		ans = (ans*256) + cur;
    }
    return ans;
}


int rand_bit_lim = 512;

int main(int argc, char *argv[])
{
	string apriv_str = "326678067141966480723856781430685230336539889799514352791880450221603428020620193050338038572171328478128398915790829758180916791763657336120768028630039";
	BigInt a_priv = Integer(apriv_str);

	srand(time(NULL));
	int i,j,k,l,n,m,ch,count=0,no_gen=0;
	
	int listenfd,listenfd1,connfd1,connfd2;
	struct sockaddr_in serv_addr, serv_addr1;
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
	
	listenfd1 = socket(AF_INET, SOCK_STREAM, 0);
	memset(&serv_addr1, '0', sizeof(serv_addr1));
	serv_addr1.sin_family = AF_INET;    
	serv_addr1.sin_addr.s_addr = htonl(INADDR_ANY); 
	serv_addr1.sin_port = htons(atoi(argv[2]));
	
	bind(listenfd1, (struct sockaddr*)&serv_addr1,sizeof(serv_addr1));

	if(listen(listenfd1, 1024) == -1 )
		{
		printf("Failed to listen\n");
		return -1;
		}


	cout<<"Waiting for clients to connect .... \n\n";
	
	int chpid = fork();
	
	if(chpid==0)
	{
		connfd1 = accept(listenfd, (struct sockaddr*)NULL ,NULL);
		printf("in child\n\n\n");
		struct csr b_csr;
		n=read(connfd1,&b_csr,sizeof(struct csr));
		
		print_csr(b_csr);
		
		sleep(1);
		
		printf("Verifying corresponding private key\n\n");
		
		BigInt pub_key = strtobig(b_csr.pub_key_str,512);		
		BigInt p = strtobig(b_csr.pr,512);
		BigInt g = strtobig(b_csr.gen,512);
		BigInt q = (p-1)/2;
		
		srand(1000);
		/////////////// use El-Gamal encryption to send a random number encrypted with the received public key
		BigInt r1 = randzp(p,rand_bit_lim);
		BigInt ch1 = randzp(p,rand_bit_lim);
		
		BigInt gxr1 = modpow(pub_key, r1, p);		gxr1 = (gxr1 * ch1)%p;
		BigInt gr1 = modpow(g,r1,p);

		cout<<"ch1 is - ";		cout<<ch1;		cout<<endl;
		//~ cout<<"gr1 is - ";		cout<<gr1;		cout<<endl;
		cout<<"gxr1 is - ";		cout<<gxr1;		cout<<endl;
		
		struct enc ch1_enc;
		bigtostr(gr1,ch1_enc.grstr,rand_bit_lim);
		bigtostr(gxr1,ch1_enc.gxrmstr,rand_bit_lim);
		write(connfd1,&ch1_enc,sizeof(struct enc));
		
		char rec_m[520]={0};
		n=read(connfd1,rec_m,sizeof(rec_m));
		
		BigInt mrec = strtobig(rec_m,rand_bit_lim);
		cout<<"Received number is - ";		cout<<mrec;		cout<<endl;
		
		if(mrec==ch1)
			printf("\nCorresponding Private key verified\n\n");
		else
			printf("\nPrivate Key NOT VERIFIED\n\n");		
		
		
		sleep(1);
				
		//~ strcpy(b_cert.name,b_csr.name);
		//~ strcpy(b_cert.mobile,b_csr.mobile);
		//~ strcpy(b_cert.email,b_csr.email);
		//~ strcpy(b_cert.aadhar,b_csr.aadhar);
		//~ strcpy(b_cert.hash_fun,b_csr.hash_fun);
		strcpy(b_cert.pub_key_str,b_csr.pub_key_str);
		//~ strcpy(b_cert.pr,b_csr.pr);
		//~ strcpy(b_cert.gen,b_csr.gen);
		//~ b_cert.key_type = b_csr.key_type;
		//~ b_cert.expire_time = time(NULL) + 100;
		BigInt sigk = randzp(q,rand_bit_lim);
		BigInt sigr = modpow(g,sigk,p);	sigr = sigr%q;
		BigInt invexp = q-2;
		BigInt sigkinv = modpow(sigk,invexp,q);
		BigInt hm = sha512(b_csr.pub_key_str,strlen(b_csr.pub_key_str));
		BigInt sigs = (sigkinv*((hm + ((a_priv * sigr)%q))%q))%q;
		
		cout<<"sign1 is - ";	cout<<sigr;	cout<<endl;
		cout<<"sign2 is - ";	cout<<sigs;	cout<<endl;
		
		bigtostr(sigr,b_cert.sign1,rand_bit_lim);
		bigtostr(sigs,b_cert.sign2,rand_bit_lim);
		write(connfd1,&b_cert,sizeof(struct new_cert));
		
		printf("\n\nB's certificate sent\n\n");

		close(connfd1);
	}
	else
	{		
		connfd2 = accept(listenfd1, (struct sockaddr*)NULL ,NULL);

		printf("In main\n");
		
		struct csr c_csr;
		n=read(connfd2,&c_csr,sizeof(struct csr));
		
		print_csr(c_csr);

		printf("Verifying corresponding private key\n\n");

		BigInt pub_key = strtobig(c_csr.pub_key_str,512);
		BigInt p = strtobig(c_csr.pr,512);
		BigInt g = strtobig(c_csr.gen,512);
		BigInt q = (p-1)/2;

		srand(2000);
		/////////////// use El-Gamal encryption to send a random number encrypted with the received public key
		BigInt r2 = randzp1(p,rand_bit_lim);
		BigInt ch2 = randzp1(p,rand_bit_lim);
		
		BigInt gxr2 = modpow(pub_key, r2, p);	gxr2 = (gxr2*ch2)%p;
		BigInt gr2 = modpow(g,r2,p);

		cout<<"ch2 is - ";		cout<<ch2;		cout<<endl;
		//cout<<"gr2 is - ";		cout<<gr2;		cout<<endl;
		cout<<"gxr2 is - ";		cout<<gxr2;		cout<<endl;
		
		struct enc ch2_enc;
		bigtostr(gr2,ch2_enc.grstr,rand_bit_lim);
		bigtostr(gxr2,ch2_enc.gxrmstr,rand_bit_lim);
		write(connfd2,&ch2_enc,sizeof(struct enc));
		
		char rec_m2[520]={0};
		n=read(connfd2,rec_m2,sizeof(rec_m2));
		
		BigInt mrec2 = strtobig(rec_m2,rand_bit_lim);
		cout<<"Received number is - ";		cout<<mrec2;		cout<<endl;
		
		if(mrec2==ch2)
			printf("\nCorresponding Private key verified\n\n");
		else
			printf("\nPrivate Key NOT VERIFIED\n\n");		
		
		
		sleep(1);
		
		//~ struct certificate c_cert;
		
		//strcpy(c_cert.name,c_csr.name);
		//strcpy(c_cert.mobile,c_csr.mobile);
		//strcpy(c_cert.email,c_csr.email);
		//strcpy(c_cert.aadhar,c_csr.aadhar);
		//strcpy(c_cert.hash_fun,c_csr.hash_fun);
		strcpy(c_cert.pub_key_str,c_csr.pub_key_str);
		//strcpy(c_cert.pr,c_csr.pr);
		//strcpy(c_cert.gen,c_csr.gen);
		//c_cert.key_type = c_csr.key_type;
		//c_cert.expire_time = time(NULL) + 100;

		BigInt sigk = randzp(q,rand_bit_lim);
		BigInt sigr = modpow(g,sigk,p);
		BigInt invexp = q-2;
		BigInt sigkinv = modpow(sigk,invexp,q);
		BigInt hm = sha512(c_csr.pub_key_str,strlen(c_csr.pub_key_str));
		BigInt sigs = (sigkinv*((hm + ((a_priv * sigr)%q))%q))%q;
		
		cout<<"sign1 is - ";	cout<<sigr;	cout<<endl;
		cout<<"sign2 is - ";	cout<<sigs;	cout<<endl;

		char sign_str[520] = {0};
		bigtostr(sigr,sign_str,rand_bit_lim);
		strcpy(c_cert.sign1,sign_str);
		bigtostr(sigs,sign_str,rand_bit_lim);
		strcpy(c_cert.sign2,sign_str);

		//~ bigtostr(sigr,c_cert.sign1,rand_bit_lim);
		//~ bigtostr(sigs,c_cert.sign2,rand_bit_lim);
		write(connfd2,&c_cert,sizeof(struct new_cert));
		
		printf("\n\nC's certificate sent\n\n");

		close(connfd2);
	}
	
	wait();
	
	close(listenfd);
	sleep(2);
	
    return 0;
}
