#include "BigInteger.cpp"

#define BigPair pair<BigInt,BigInt>
#define zero Integer(0)
#define one Integer(1)

BigInt MOD = Integer("61"); // or p
BigInt a = Integer("2");  // a is -3, but since we cannot represent -ve in bigint we do it -3
//~ BigInt b = Integer("2455155546008943817740293915197451784769108058161191238065");
//~ BigInt n = Integer("6277101735386680763835789423176059013767194773182842284081");


BigInt inf = Integer("100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");  // just to represent infinity
BigPair ecc_INF = make_pair(inf,inf);

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
	ans.X = ( ((m*m) + MOD + MOD + MOD) - (P.X%MOD + Q.X%MOD)%MOD )%MOD;    //MOD is added because -ve BIGINT is not defined
	ans.Y = ( m*(((P.X + MOD) - ans.X) + MOD) - P.Y%MOD )%MOD;
	return ans;
}

BigPair point_double(BigPair P)
{
	if(P.Y==0) // in point doubling if Y cordinate is 0 then point doubling is INFINITY
	return ecc_INF;
	
	//~ BigInt m = (3*P.X + a) / (2*P.Y);
	BigInt m = ( (3*P.X + a) * modpow( (2*P.Y), MOD-2, MOD )  )%MOD;
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

int main()
{
	//BigInt p = Integer("6277101735386680763835789423207666416083908700390324961279");
		
	BigPair G = make_pair( Integer("2"), Integer("4") );
	
	BigInt xx=Integer("2");
	printPair(point_double(G));
	//~ BigPair ans = ecc_mult(G,xx);
	//~ printPair(ans);
	
}
