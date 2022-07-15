#pragma once
#include <stdexcept>
#include <vector>
#include <string>
#include <sstream>
#include <limits>

class ArgumentParser : public std::vector<std::string>
{
public:
	//ArgumentParser();
	ArgumentParser(int argc, const char** argv);
	~ArgumentParser();

	size_t find(const std::string& arg_name) const;
	size_t find(const std::string& arg_name, size_t search_begin) const;

	template<typename T> T  get              (const std::string& arg_mame);
	template<typename T> T  get              (const std::string& arg_name, const T& default_data);

	template<typename T>
	class Iterator
	{
	public:
		Iterator(ArgumentParser *ap, const std::string& param_name);

		T operator*() const;
		bool operator==(const Iterator& r) const;
		bool operator!=(const Iterator& r) const;
		Iterator& operator++();
	private:
		Iterator(){};

		std::string param_name;
		mutable size_t pos{0};
		ArgumentParser *ap;

		friend ArgumentParser;
	};

	template<typename T>
	Iterator<T> begin(const std::string& param_name);
	template<typename T>
	Iterator<T> end();

	//constants
	static constexpr size_t not_found{std::numeric_limits<size_t>::max()}; // Equivalently size_t(-1)
private:
};

#include "ArgumentParser.inl"