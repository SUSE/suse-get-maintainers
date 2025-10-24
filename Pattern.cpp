#include <iostream>

#include <sl/git/StrArray.h>

#include <git2.h>

#include "Pattern.h"

using namespace SGM;

constexpr unsigned int Pattern::pattern_weight(const std::string &pattern)
{
	unsigned ret = 1;
	bool seen = false;
	for (const char c: pattern) {
		switch (c) {
		case '/':
			seen = true;
			break;
		case ' ':
		case '\n':
		case '\t':
		case '\r':
		case '\\':
			break;
		default:
			if (seen) {
				++ret;
				seen = false;
			}
		}
	}
	return ret;
}

std::optional<SGM::Pattern> SGM::Pattern::create(const std::string_view &p)
{
	std::string pattern{p};
	if (!pattern.empty() && pattern.back() == '/' &&
			pattern.find_first_of('*') != std::string::npos)
		pattern.push_back('*');

	git_pathspec *pathspec;
	if (git_pathspec_new(&pathspec, SlGit::StrArray({ pattern.c_str() }))) {
		std::cerr << git_error_last()->message << '\n';
		return std::nullopt;
	}

	return Pattern(pathspec, pattern_weight(pattern));
}
