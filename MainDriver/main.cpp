#include <iostream>
#include <boost/log/trivial.hpp>

int main() {
	std::cout << "hi!\n";
	BOOST_LOG_TRIVIAL(info) << "HII!";
}
