/*
 * CPProxy:
 *  https://github.com/Thorek777/cpproxy
 *
 * Library powered by:
 *  https://proxycheck.io
 *  https://think-async.com/Asio
 *  https://github.com/nlohmann/json
 */

#pragma once

#include "asio/asio.hpp"
#include "json/json.hpp"

class cpproxy_core
{
protected:
#if __cplusplus < 201703L
	using cpproxy_string = std::string;
#else
	using cpproxy_string = std::string_view;
#endif

#if __cplusplus <= 201703L
	using cpproxy_thread = std::thread;
#else
	using cpproxy_thread = std::jthread;
#endif
};

class cpproxy_asio : public cpproxy_core
{
protected:
	std::unordered_map<cpproxy_string, asio::ip::tcp::iostream> map_;

	static auto make_asio_iostream(const cpproxy_string& ip)
	{
		asio::ip::tcp::iostream stream("proxycheck.io", "http");

		stream << "POST /v2/" << ip << "?vpn=1&asn=1 HTTP/1.0\r\n";
		stream << "Host: proxycheck.io\r\n";
		stream << "Accept: */*\r\n";
		stream << "Content-Type: text/plain\r\n";
		stream << "Content-Length: 2\r\n";
		stream << "Connection: close\r\n\r\n";
		stream << "{}";

		return stream;
	}
};

class cpproxy_json : public cpproxy_asio
{
protected:
	struct s_ip
	{
		bool status;
		bool proxy;
	};

	static auto parse_json(const cpproxy_string& object)
	{
		s_ip ip = {};

		// ReSharper disable once CppTooWideScopeInitStatement
		const auto json = nlohmann::json::parse(object);

		for (const auto& it : json.items())
		{
			if (!it.value().is_object())
				ip.status = it.value() == "ok" ? true : false;

			if (it.value().is_object())
				ip.proxy = it.value().at("proxy") == "yes" ? true : false;
		}

		return ip;
	}

	static auto cleanup_json(const asio::ip::tcp::iostream& object)
	{
		std::string string(std::istreambuf_iterator(object.rdbuf()), {});
		return string.erase(0, string.find('{'));
	}
};

class cpproxy : public cpproxy_json
{
public:
	void add(const cpproxy_string& ip, const bool force_check = false)
	{
		map_.emplace(ip, !force_check ? asio::ip::tcp::iostream() : make_asio_iostream(ip));
	}

	void scan()
	{
		std::vector<cpproxy_thread> threads;

		for (auto& [fst, snd] : map_)
		{
			if (snd.get() != -1)
				continue;

			threads.emplace_back([this, &fst, &snd]
				{
					snd = make_asio_iostream(fst);
				}
			);
		}

#if __cplusplus <= 201703L
		for (auto& it : threads)
			it.join();
#endif
	}

	bool is_proxy(const cpproxy_string& ip)
	{
		if (const auto element = map_.find(ip); element == map_.end())
			throw std::exception("cpproxy::is_proxy - element not found in map.\n");
		else
		{
			if (const auto [fst, snd] = parse_json(cleanup_json(element->second)); fst)
				return snd;

			throw std::exception("cpproxy::is_proxy - status is not true.\n");
		}
	}
};
