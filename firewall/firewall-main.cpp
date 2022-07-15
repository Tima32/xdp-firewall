#include <iostream>
#include "ArgumentParser.hpp"

using namespace std;

int main(int argc, const char** argv)
{
	ArgumentParser ap(argc, argv);

	try
	{
		for (size_t pos = 0; pos != -1 && pos < ap.size(); pos++)
		{
			pos = ap.find("-f", pos);
			cout << ap[pos] << " " << pos << endl;
		}		
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << '\n';
		exit(-1);
	}
	

	cout << "Hello world" << endl;
	return 0;
}
