#include <iostream>
#include <fstream>
using namespace std;

int main()
{
  ifstream in("file.txt");

  if(!in) {
    cout << "Cannot open input file.\n";
    return 1;
  }

  string s;
  in>>s;
  in.close();
  
  cout<<s;

  

  return 0;
}
