#include<fstream>
#include<bits/stdc++.h>
using namespace std;
int main()
{
	ifstream file("abc.txt");
	
	string str[6];
	int i=0;
	
	while( std::getline( file, str[i++] ) );
    
    cout<<str[0]<<"\n"<<str[1]<<"\n"<<str[2]<<"\n"<<str[3]<<"\n";
}
