/*
 * CPProxy:
 *  https://github.com/Thorek777/cpproxy
 *
 * Library powered by:
 *  https://proxycheck.io
 *  https://think-async.com/Asio
 *  https://github.com/nlohmann/json
 */

#include <fstream>
#include <iostream>

#include "cpproxy.hpp"

int main()
{
	try
	{
		cpproxy checker;

		// https://free-proxy-list.net
		checker.add("198.199.86.11");
		checker.add("157.230.48.102");
		checker.add("154.61.143.238");
		checker.add("200.105.215.22");
		checker.add("139.99.237.62");
		checker.add("51.15.242.202");
		checker.add("45.32.245.26");
		checker.add("157.254.193.139");
		checker.add("146.83.128.23");
		checker.add("43.255.113.232");

		checker.scan();

		if (checker.is_proxy("43.255.113.232"))
			std::cout << "IP is proxy!\n";
		else
			std::cout << "IP is not proxy!\n";

		std::ofstream file("output.json");

		checker.to_stream(file);
	}
	catch (const std::exception& message)
	{
		std::cout << message.what();
	}
}
