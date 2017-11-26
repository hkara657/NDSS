///////////////////////////////////////////////////////////////////
////////////////   Extended Euclid's Algorithm for  ///////////////
////////////////       Multiplicative Inverse       ///////////////
///////////////////////////////////////////////////////////////////


#include <bits/stdc++.h>
#include "BigInteger.cpp"
using namespace std;

int main()
{
	srand(time(NULL));
	int i,j,k,l,n,m,ch,count=0,no_gen=0;
	string zero="0";
	string one="1";
	BigInt x1=Integer(one);
	BigInt x2=Integer(zero);
	BigInt y1=Integer(zero);
	BigInt y2=Integer(one);

	BigInt t1,t2,t3,q,mi,ex;
	string tp;

	cout<<"Enter 512-bit prime number - ";
	cin>>tp;
	BigInt f =  Integer(tp);
	BigInt  x3 = Integer(tp);
	cout<<"Enter the number whose inverse is to be found - ";
	cin>>tp;
	BigInt  d = Integer(tp);
	BigInt  y3 = Integer(tp);


	cout<<"\n\n";
	cout<<"**************************************************************************\n\n";
	cout<<"Running Extended Euclidean Algorithm to find Multiplicative Modulo Inverse\n\n";
	cout<<"**************************************************************************\n\n";

	

	clock_t begin = clock();
	
	while(y3>1)
	{
		//~ cout<<x1;		//~ cout<<x2;		//~ cout<<x3;		//~ cout<<endl;
		//~ cout<<y1;		//~ cout<<y2;		//~ cout<<y3;		//~ cout<<q;		//~ cout<<endl<<endl;

		q = x3/y3;
		if((q*y1)>x1)
		{
			t1 = x1 + f;
			ex = (q*y1);
			ex %=f;
			t1 = t1 - ex;
		}
		else
			t1 = x1-(q*y1);

		if((q*y2)>x2)
		{
			t2 = x2 + f;
			ex = (q*y2);
			ex %=f;
			t2 = t2 - ex;
		}
		else
			t2 = x2-(q*y2);

		if((q*y3)>x3)
		{
			t3 = x3 + f;
			ex = (q*y3);
			ex %=f;
			t3 = t3 - ex;
		}
		else
			t3 = x3-(q*y3);
				
		x1=y1;		x2=y2;		x3=y3;
		y1=t1;		y2=t2;		y3=t3;
	}

		//~ cout<<x1;		//~ cout<<x2;		//~ cout<<x3;		//~ cout<<endl;
		//~ cout<<y1;		//~ cout<<y2;		//~ cout<<y3;		//~ cout<<q;		//~ cout<<endl<<endl;

	if(y3==0)
	{
		cout<<"No inverse found\n GCD is - ";
		cout<<y2;
		cout<<"\n\n";
		clock_t end = clock();
		double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
		cout<<"Time taken to find the GCD of numbers is "<<time_spent<<" seconds"<<endl;
		cout<<"\n\n\n";
	}
	else if(y3==1)
	{
		cout<<"The inverse is - ";
		//~ y2 += f;
		//~ y2 %= f;
		cout<<y2;
		
		cout<<"\n\n";
		
		clock_t end = clock();
		double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
		cout<<"Time taken to find the multiplicative inverse number is "<<time_spent<<" seconds"<<endl;
		
		cout<<"\n\n\n";
		

		cout<<"************************************\n\n";
		cout<<"******* Proof of correctness *******\n\n";
		cout<<"************************************\n\n";
		
		cout<<"Prime nummber (f)- ";
		cout<<f;
		cout<<"\n\n";
		cout<<"Input nummber (d)- ";
		cout<<d;
		cout<<"\n\n";
		cout<<"Inverse of nummber found by algorithm (y2) - ";
		cout<<y2;
		cout<<"\n\n";
		cout<<" (d x y2) = ";
		BigInt  mul1 = d*y2;
		cout<<mul1;
		cout<<"\n\n";
		cout<<" (d x y2) mod f = ";
		cout<<mul1%f;
		cout<<"\n\nHence Proved.\n\n\n";
	}
	
	
    return 0;
}