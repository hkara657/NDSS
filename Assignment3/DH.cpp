#include "GeneratePrime.cpp"
int num_bits=128;
int main()
{
	BigInt p = random_primes(num_bits); // order of group  p is prime
	cout<<p;EL;
	
	BigInt g = random_primes(30); // generator of group
	
	BigInt a = random_primes(num_bits/2);  // secret key of Alice
	cout<<"secret key with Alice is   ";cout<<a;EL;
	BigInt b = random_primes(num_bits/2 - 5);  // secret key of Bob
	cout<<"secret key with Bob is      ";cout<<a;EL;
	
	BigInt A = modpow(g, a, p);  // g^a mod p   sent by A to B
	BigInt B = modpow(g, b, p);
	
	BigInt keyA = modpow(B,a,p);
	BigInt keyB = modpow(A,b,p);
	cout<<"shared key with Alice is   ";cout<<keyA;EL;
	cout<<"shared key with Bob is     ";cout<<keyB;EL;
}
