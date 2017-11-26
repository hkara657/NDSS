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

//#define MAC_PRINT

using namespace std;


class point
{
	public:
	BigInt x;
	BigInt y;
	
	point()
	{
		x=Integer(0);
		y=Integer(0);
	}
};

////// my own exponentiation function 
BigInt modpow(BigInt a, BigInt b, BigInt mod) {
	string one="1";
	BigInt ans = Integer(one);
	a%=mod;
	while(b>0)
	{
		fflush(stdout);
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

BigInt powfast(BigInt a, int b) {
	BigInt ans = Integer(1);
	while(b>0)
	{
		if(b%2==1)
			ans*=a;
		a*=a;
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

BigInt randzp(BigInt p,int max_bits)
{
	BigInt g;
	do
	{
		int cur_bits = rand()%max_bits;
		BigInt rand1 = genrand(cur_bits);
		g = rand1;
		g = g % p;
	}while(g==one || g==zero || g<10000000);
	return g;
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

int conv(char c)
{
	if(c>='0' && c<='9')
		return c-'0';
	else
		return c-'A'+10;
}

BigInt convhex(char inp[],int len)
{
	BigInt ans = zero;
	for(int i=0;i<len;i++)
	{
		ans *= 16;
		ans += conv(inp[i]);
	}
	return ans;
}

BigInt modinv(BigInt a,BigInt p)
{
	BigInt exp = p-2;  ///// Fermat's last theorem	
	BigInt ans = modpow(a,exp,p);
	
	return ans;
}

point addition(point P, point Q, BigInt p, BigInt a)   //// includes point doubling also - only slope is different
{
	point R;
	BigInt m = zero;
	

	BigInt tp = ((P.x + p)-Q.x)%p;
	BigInt tp6 = modinv(tp,p);

	m = ((P.y + p)-Q.y)%p;	
	m = (m*tp6)%p;
	
	BigInt tp1 = (m*m)%p;
	BigInt tp2 = (P.x+Q.x)%p;
	
	BigInt tp3 = ((tp1+p)-tp2)%p;
	
	R.x = tp3;
	
	BigInt tp4 = ((P.x+p)-R.x)%p;
	BigInt tp5 = (tp4*m)%p;
	tp5 = ((tp5+p)-P.y)%p;
	
	R.y = tp5;
	
	return R;
}

point doubling(point P,BigInt p, BigInt a)
{
	point R;
	BigInt m = zero;

	BigInt tp = (P.y * 2)%p;
	BigInt tp7 = modinv(tp,p);

	m = (P.x * P.x)%p;	
	m = (m*3)%p;
	m = (m+a) %p;	
	m = (m*tp7)%p;
	
	BigInt tp1 = (m*m)%p;	
	BigInt tp2 = (P.x*2)%p;
	
	BigInt tp3 = ((tp1+p)-tp2)%p;

	R.x = tp3;
	
	BigInt tp4 = ((P.x+p)-R.x)%p;
	
	tp4 = (tp4*m)%p;
	tp4 = ((tp4+p)-P.y)%p;
		
	R.y = tp4;

	return R;
}

point scalarmult(point P, BigInt exp, BigInt p, BigInt a)
{
	point R,Q;
	int fl=-1;
	Q.x = P.x;
	Q.y = P.y;
	
	cout<<"Computing Scalar multiplication - \n";
	while(exp>0)
	{
		cout<<".";
		fflush(stdout);
		if(exp%2==1)
		{
			if(fl==-1)
			{
				R.x = Q.x;
				R.y = Q.y;
				fl=1;
			}
			else
			{
				R = addition(R,Q,p,a);
			}
		}
		Q = doubling(Q,p,a);
		exp /= 2;
	}
	cout<<endl;

	return R;
}

int main(int argc,char *argv[])
{
	srand(time(NULL));
	int i,j,k,l,n,m,ch,count=0,no_gen=0;
	double total_time_1=0,total_time_2=0;

	int rand_bit_lim = 192;
	int p_bits = 192;

	double time_spent;
	double total_time=0.0;
	clock_t begin,end;
	
	
	cout<<"Generating public parameters - \n\n";
	
	begin = clock();
	
	
	BigInt p = ((powfast(two,192) - powfast(two,64)) - 1);
	BigInt a = p-3;   ///// can't use a = -3 in this library. so using p-3 ... 

	//~ string pri = "97";
	//~ BigInt p = Integer(pri);
	//~ BigInt a = Integer(2);

	point g;
	
	//~ string gpox = "3";
	//~ string gpoy = "6";
	
	//~ g.x = Integer(gpox);
	//~ g.y = Integer(gpoy);
	
//	char ninp[512] = "000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409";

	char gxinp[512] = "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012";
	char gyinp[512] = "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811";
	
	g.x = convhex(gxinp,strlen(gxinp));
	g.y = convhex(gyinp,strlen(gyinp));
	
		
	cout<<"p is \n";
	cout<<p;
	cout<<endl;

	cout<<"G.x is \n";
	cout<<g.x;
	cout<<"\nG.y is \n";
	cout<<g.y;
	cout<<endl;
	
	//~ BigInt expo = Integer(7);	
	//~ point R = scalarmult(g,expo,p,a);
	//~ cout<<"R.x is \n";
	//~ cout<<R.x;
	//~ cout<<"\nR.y is \n";
	//~ cout<<R.y;
	//~ cout<<endl;
	

		
	end=clock();
	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	total_time += time_spent;

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
	char g_xBuff[1024]={0};
	char g_yBuff[1024]={0};
	
	char gx_xBuff[1024]={0};
	char gx_yBuff[1024]={0};
	
	char gy_xBuff[1024]={0};
	char gy_yBuff[1024]={0};
	
	char gxy_xBuff[1024]={0};
	char gxy_yBuff[1024]={0};
	
	cout<<"Now start other party\n\nWaiting for other party to connect .... \n\n";
	
	connfd = accept(listenfd, (struct sockaddr*)NULL ,NULL);


	bigtostr(p,pBuff,p_bits);
	n=write(connfd,pBuff,strlen(pBuff));
	sleep(2);
	
	bigtostr(g.x,g_xBuff,p_bits);
	n=write(connfd,g_xBuff,strlen(g_xBuff));
	
	sleep(1);
	
	bigtostr(g.y,g_yBuff,p_bits);
	n=write(connfd,g_yBuff,strlen(g_yBuff));	

/////// choose x and send g^x 	
	begin = clock();

	BigInt x = randzp(p,rand_bit_lim);
	cout<<"x is ";
	cout<<x;
	
	point xG = scalarmult(g,x,p,a);	
	cout<<"xG.x is ";
	cout<<xG.x;
	cout<<endl;
	cout<<"xG.y is ";
	cout<<xG.y;
	cout<<endl;
	
	unsigned char gx_xmacinp[1024]={0};
	char gx_xmac[1024] = {0};
	bigtostr(xG.x,gx_xBuff,p_bits);
	int gx_xinplen = strtounsch(gx_xBuff,p_bits,gx_xmacinp);
	int gx_xmaclen = cmac_compute(gx_xmacinp,gx_xinplen,gx_xmac);


	unsigned char gx_ymacinp[1024]={0};
	char gx_ymac[1024] = {0};
	bigtostr(xG.y,gx_yBuff,p_bits);
	int gx_yinplen = strtounsch(gx_yBuff,p_bits,gx_ymacinp);
	int gx_ymaclen = cmac_compute(gx_ymacinp,gx_yinplen,gx_ymac);
	
	end = clock();

	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	total_time += time_spent;
	
	#ifdef MAC_PRINT
		cout<<"MAC(xG.x) is \n";
		cout<<gx_xmac<<endl;
		cout<<"MAC(xG.y) is \n";
		cout<<gx_ymac<<endl;
	#endif
	
	strcpy(gx_xBuff+p_bits,gx_xmac);
	n=write(connfd,gx_xBuff,strlen(gx_xBuff));
	
	sleep(1);
	
	
///// receive yG.x
	n=read(connfd,gy_xBuff,1024);
	
	begin = clock();
		
	char x_macbuff[150] = {0};
	for(i=p_bits; i<(p_bits+128);i++)
		x_macbuff[i-p_bits] = gy_xBuff[i];	
	gy_xBuff[p_bits]=0;
	
	point yG;
	
	yG.x = strtobig(gy_xBuff,p_bits);
	cout<<"\nyG.x received is ";
	cout<<yG.x;
	cout<<endl;
	#ifdef MAC_PRINT
		cout<<"MAC(yG.x) received is \n"<<x_macbuff<<endl<<endl;
	#endif
	
	unsigned char gy_xmacinp[1024]={0};
	char gy_xmac[1024] = {0};	
	int gy_xinplen = strtounsch(gy_xBuff,p_bits,gy_xmacinp);
	int gy_xmaclen = cmac_compute(gy_xmacinp,gy_xinplen,gy_xmac);

	#ifdef MAC_PRINT
		cout<<"MAC(yG.x) computed is \n"<<gy_xmac<<endl<<endl;
	#endif
	
	for(i=0;i<128;i++)
	{
		if(x_macbuff[i]!=gy_xmac[i])
			break;
	}
	if(i!=128)
	{
		cout<<"Error : MAC does not match\n\n";
		return 0;
	}
	else
		cout<<"MAC(yG.x) verified\n\n";	
	end = clock();
	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	total_time += time_spent;
	
/////////////////////////	
	strcpy(gx_yBuff+p_bits,gx_ymac);
	n=write(connfd,gx_yBuff,strlen(gx_yBuff));
////////////////////////

///// receive yG.y
	n=read(connfd,gy_yBuff,1024);
	
	begin = clock();
		
	char y_macbuff[150] = {0};
	for(i=p_bits; i<(p_bits+128);i++)
		y_macbuff[i-p_bits] = gy_yBuff[i];	
	gy_yBuff[p_bits]=0;
	
	yG.y = strtobig(gy_yBuff,p_bits);
	cout<<"\nyG.y received is ";
	cout<<yG.y;
	cout<<endl;
	#ifdef MAC_PRINT
		cout<<"MAC(yG.y) received is \n"<<y_macbuff<<endl<<endl;
	#endif
	
	unsigned char gy_ymacinp[1024]={0};
	char gy_ymac[1024] = {0};	
	int gy_yinplen = strtounsch(gy_yBuff,p_bits,gy_ymacinp);
	int gy_ymaclen = cmac_compute(gy_ymacinp,gy_yinplen,gy_ymac);
	
	#ifdef MAC_PRINT
		cout<<"MAC(yG.y) computed is \n"<<gy_ymac<<endl<<endl;
	#endif
	
	for(i=0;i<128;i++)
	{
		if(y_macbuff[i]!=gy_ymac[i])
			break;
	}
	if(i!=128)
	{
		cout<<"Error : MAC does not match\n\n";
		return 0;
	}
	else
		cout<<"MAC(yG.y) verified\n\n";	
	

	point xyG = scalarmult(yG,x,p,a);
	
	cout<<"x(yG).x is ";
	cout<<xyG.x;
	cout<<endl;
	cout<<"x(yG).y is ";
	cout<<xyG.y;
	cout<<endl;
	
	char final_key[1024]={0};
	
	bigtostr(xyG.x,gxy_xBuff,p_bits);   ///// ECDH shared key is x co-ordinate shared point
	int key_len = sha256(gxy_xBuff,p_bits,final_key);
	final_key[128]=0;  ///// truncate output to 128 bits
	
	cout<<"\n\nFinal 128-bit key is - \n"<<final_key<<"\n\n";
	
	end = clock();
	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	total_time += time_spent;


	cout<<"Time taken to compute keys (excluding network delay) = "<<total_time<<" seconds\n\n";
	
	
	
    return 0;
}
