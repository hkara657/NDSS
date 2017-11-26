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
#include <string.h>
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
	char sign1[512];
	char sign2[512];
};
#pragma pack(0)


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
	str[max_bits]=0;
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
	string apub_str = "2705238749646066724771231150830766271581717550656945181222618455342205048492357042917956193731107376251942808983029407803261086161020014320612463906642362";
	BigInt a_pub = Integer(apub_str);

	srand(time(NULL));
	int i,j,k,l,n,m,ch,count=0,no_gen=0;
	int rand_bit_lim = 512;
	int p_bits = 512;
	
	cout<<"Generating public parameters - \n\n";
	
	string pri = "11394884647602561200739195439210799667827406275129711954880070420859840417872988165182257949052349866437867857014785512379989629646924405020239723585249547";	
	BigInt p = Integer(pri);  ///// prime for Zp
	string gstr = "3303479677421781979816554780593878886835152597202295744999301126814881463529064480620179417847086007265847256886951043101193452650621812647114842253228067";
	BigInt g = Integer(gstr);
	BigInt q = (p-1)/2;

	cout<<"p is ";	cout<<p;	cout<<endl;
	cout<<"g is ";	cout<<g;	cout<<endl;

	BigInt x = randzp(q,rand_bit_lim);
	BigInt gx = modpow(g, x, p);
	
	cout<<"x is ";	cout<<x;	cout<<endl;
	cout<<"g^x is ";	cout<<gx;	cout<<endl;

	int sockfd;
	int port_t;
	char ip_t[100];

	struct sockaddr_in client_addr;

	strcpy(ip_t,argv[1]);
	port_t=atoi(argv[2]);
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(port_t);
	client_addr.sin_addr.s_addr = inet_addr(ip_t);
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	connect(sockfd, (struct sockaddr *)&client_addr, sizeof(client_addr));
	
	sleep(1);

	struct csr cur_csr;
	
	strcpy(cur_csr.name,"Node B");
	strcpy(cur_csr.mobile,"8277543940");
	strcpy(cur_csr.email,"nodeb@csa.iisc.ernet.in");
	strcpy(cur_csr.aadhar,"775465982465");
	cur_csr.key_type = 0;
	bigtostr(gx,cur_csr.pub_key_str,512);
	bigtostr(p,cur_csr.pr,512);
	bigtostr(g,cur_csr.gen,512);
	strcpy(cur_csr.hash_fun,"SHA512");	
	
	write(sockfd,&cur_csr,sizeof(struct csr));

	sleep(1);
	
	struct enc ch1_enc;
	n=read(sockfd,&ch1_enc,sizeof(struct enc));
	BigInt gr = strtobig(ch1_enc.grstr,rand_bit_lim);
	BigInt gxrm = strtobig(ch1_enc.gxrmstr,rand_bit_lim);
	
	//~ cout<<"gr is - ";	cout<<gr;	cout<<endl;	
	//~ cout<<"gxrm is - ";	cout<<gxrm;	cout<<endl;
	
	BigInt grx = modpow(gr,x,p);
	BigInt exp = p - 2;
	BigInt grxinv = modpow(grx,exp,p);	
	BigInt cm = gxrm * grxinv;
	cm = cm % p;

	cout<<"cm is - ";	cout<<cm;	cout<<endl;
	
	char m_str[520]={0};
	bigtostr(cm,m_str,rand_bit_lim);
	
	write(sockfd,m_str,strlen(m_str));
	sleep(1);
	
	
	struct certificate cert_of_b;
	n=read(sockfd,&cert_of_b,sizeof(struct certificate));

	
	printf("B's certificate received.....\n\n\n Press ENTER when node C is ready\n\n");
	getchar();

	
	int listenfd,connfd;
	struct sockaddr_in serv_addr;
	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&serv_addr, '0', sizeof(serv_addr));
	serv_addr.sin_family = AF_INET; 
	serv_addr.sin_addr.s_addr = inet_addr(argv[3]); 
	serv_addr.sin_port = htons(atoi(argv[4]));
		
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
	
	cout<<"Now start C\n\nWaiting for C to connect .... \n\n";
	
	connfd = accept(listenfd, (struct sockaddr*)NULL ,NULL);
	
	write(connfd,&cert_of_b,sizeof(struct certificate));
	sleep(1);
	
	struct certificate cert_of_c;
	n=read(connfd,&cert_of_c,sizeof(struct certificate));
	printf("C's certificate received\n");
	
	printf("\nVerifying C's certificate with Public key of A\n\n");
	
	//~ cout<<cert_of_c.sign1<<endl;
	//~ cout<<cert_of_c.sign2<<endl<<endl;
	
	BigInt s = strtobig(cert_of_c.sign2,512);
	BigInt invexp = q-2;
	BigInt w = modpow(s,invexp,q);
	BigInt hm = sha512(cert_of_c.pub_key_str, strlen(cert_of_c.pub_key_str));
	BigInt u1 = (hm*w)%q;
	BigInt r = strtobig(cert_of_c.sign1,512);	r=r%q;
	BigInt u2 = (r*w)%q;
	BigInt gu1 = modpow(g,u1,p);
	BigInt yu2 = modpow(a_pub,u2,p);
	BigInt v = ((gu1 * yu2) %p)%q;
	
	cout<<"s is - ";	cout<<s;	cout<<endl;
	cout<<"r is - ";	cout<<r;	cout<<endl;
	cout<<"v is - ";	cout<<v;	cout<<endl;
	
	
	if(v!=r || time(NULL)>cert_of_c.expire_time)
	{
		printf("\nC's certificate is NOT VALID\n");
		return 0;
	}
	else
		printf("\nC's certificate is valid\n");
	
	sleep(2);
	
	printf("\n\n\nNow computing Diffie Hellman shared secret key  ..... \n\n");
	
	cout<<"x is ";	cout<<x;	cout<<endl;
	cout<<"g^x is ";	cout<<gx;	cout<<endl;
	
	unsigned char gxmacinp[1024]={0};
	char gxmac[1024] = {0};
	bigtostr(gx,gxBuff,p_bits);
	int gxinplen = strtounsch(gxBuff,p_bits,gxmacinp);
	int gxmaclen = cmac_compute(gxmacinp,gxinplen,gxmac);
	
	cout<<"MAC(g^x) is \n";
	cout<<gxmac<<endl;
	
	strcpy(gxBuff+p_bits,gxmac);
	write(connfd,gxBuff,strlen(gxBuff));
	
///// receive g^y	
	n=read(connfd,gyBuff,1024);

	char macbuff[150] = {0};
	for(i=p_bits; i<(p_bits+128);i++)
		macbuff[i-p_bits] = gyBuff[i];	
	gyBuff[p_bits]=0;
	
	BigInt gy = strtobig(gyBuff,p_bits);
	cout<<"\ng^y received is ";	cout<<gy;	cout<<endl;
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
	cout<<"(g^y)^x is ";	cout<<gyx;	cout<<endl;
	
	char final_key[1024]={0};
	
	bigtostr(gyx,gxyBuff,p_bits);
	int key_len = sha256(gxyBuff,p_bits,final_key);
	final_key[128]=0;  ///// truncate output to 128 bits
	
	cout<<"\n\nFinal 128-bit key is - \n"<<final_key<<"\n\n";
	
	
	close(sockfd);
	close(connfd);
    return 0;
}
