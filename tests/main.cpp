/*
 *   ___ _ __  _ __  _ __ _____  ___   _
 *  / __| '_ \| '_ \| '__/ _ \ \/ / | | |
 * | (__| |_) | |_) | | | (_) >  <| |_| |
 *  \___| .__/| .__/|_|  \___/_/\_\\__, |
 *      |_|   |_|                  |___/ https://github.com/Thorek777/cpproxy
 *
 * For modern C++.
 * Required dependencies:
 *   https://proxycheck.io
 *   https://think-async.com/Asio
 *   https://github.com/nlohmann/json
 */

#include <iostream>

#include "cpproxy.hpp"

int main()
{
	cpproxy checker;

	checker.add("localhost");

	checker.scan();

	if (const auto [status, is_proxy] = checker.read("localhost"); status)
	{
		std::cout << "Status of IP is ok.\n";

		if (is_proxy)
			std::cout << "This IP is proxy!\n";
		else
			std::cout << "This IP is not proxy!\n";
	}
}
