#pragma once
#include<string>
#include<vector>

namespace util
{
	void split(const std::string& s, std::vector<std::string>& tokens, const char& delim = ' ');
}
