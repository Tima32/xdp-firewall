#pragma once
#include "ArgumentParser.hpp"

inline ArgumentParser::ArgumentParser(int argc, const char** argv)
{
	for (int i = 0; i < argc; ++i)
		emplace_back(argv[i]);
}
inline ArgumentParser::~ArgumentParser()
{
}

inline size_t ArgumentParser::find(const std::string& arg_name) const
{
	for (size_t i = 0; i < size(); ++i)
		if (operator[](i) == arg_name)
			return i;
	return size_t(-1);
}
inline size_t ArgumentParser::find(const std::string& arg_name, size_t search_begin) const
{
	for (size_t i = search_begin; i < size(); ++i)
		if (operator[](i) == arg_name)
			return i;
	return size_t(-1);
}

template<typename T>
inline T ArgumentParser::get(const std::string& arg_mame)
{
	size_t pos = find(arg_mame);
	if (pos == -1)
		throw std::logic_error("Argument not found.");
	if (pos + 1 == size())
		throw std::logic_error("There is no data behind the argument.");

	std::stringstream ss;
	ss << operator[](pos + 1);
	T data;
	ss >> data;

	return data;
}
template<>
inline std::string ArgumentParser::get(const std::string& arg_name)
{
	size_t pos = find(arg_name);
	if (pos == -1)
		throw std::logic_error("Argument not found.");
	if (pos + 1 == size())
		throw std::logic_error("There is no data behind the argument.");

	return operator[](pos + 1);
}
template<typename T>
inline T ArgumentParser::get(const std::string& arg_name, const T& default_data)
{
	try
	{
		T data = get<T>(arg_name);
		return data;
	}
	catch (const std::logic_error&)
	{
		return default_data;
	}
}

template<typename T>
inline ArgumentParser::Iterator<T>::Iterator(ArgumentParser *ap, const std::string& param_name):
	ap(ap), param_name(param_name){}
template<typename T>
inline T ArgumentParser::Iterator<T>::operator*() const
{
	auto param_pos = ap->find(param_name, pos);
	pos = param_pos;
	if (param_pos == -1)
		throw std::out_of_range("Out of range");

	if (param_pos + 1 == ap->size())
		throw std::logic_error("There is no data behind the argument.");
	
	std::stringstream ss;
	ss << ap->operator[](param_pos + 1);
	T data;
	ss >> data;

	return data;
}
template<typename T>
inline bool ArgumentParser::Iterator<T>::operator==(const Iterator& r) const
{
	if (ap != r.ap)
		return false;
	if (pos == -1 && r.pos == -1)
		return true;
	if (pos != r.pos)
		return false;
	if (param_name != r.param_name)
		return false;
	
	return true;
}
template<typename T>
inline bool ArgumentParser::Iterator<T>::operator!=(const Iterator& r) const
{
	if (ap != r.ap)
		return true;
	if (pos == -1 && r.pos == -1)
		return false;
	if (pos != r.pos)
		return true;
	if (param_name != r.param_name)
		return true;
	
	return true;
}
template<typename T>
inline ArgumentParser::Iterator<T>& ArgumentParser::Iterator<T>::operator++()
{
	if (pos != -1)
		++pos;
	return *this;
}

template<typename T>
inline ArgumentParser::Iterator<T> ArgumentParser::begin(const std::string& param_name)
{
	Iterator<T> ap{ this, param_name };
	ap.pos = find(param_name);
	return ap;
}
template<typename T>
inline ArgumentParser::Iterator<T> ArgumentParser::end()
{
	Iterator<T> i(this, "");
	i.pos = size();
	return i;
}