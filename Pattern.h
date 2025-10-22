#ifndef SGM_PATTERN_H
#define SGM_PATTERN_H

#include <filesystem>
#include <git2.h>
#include <string>

#include "helpers.h"

namespace SGM {

struct Pattern {
	Pattern(std::string_view p) {
		std::string pattern{p};
		m_weight = pattern_weight(pattern);
		if (!pattern.empty() && pattern.back() == '/' &&
				pattern.find_first_of('*') != std::string::npos)
			pattern.push_back('*');
		const char *ptr = pattern.c_str();
		const git_strarray array{.strings=const_cast<char **>(&ptr), .count=1};
		if (git_pathspec_new(&m_pathspec, &array))
			fail_with_message(git_error_last()->message);
	}
	~Pattern() { git_pathspec_free(m_pathspec); }
	Pattern& operator=(Pattern& p) = delete;
	Pattern(Pattern& p) = delete;
	Pattern& operator=(Pattern&& p) = delete;
	Pattern(Pattern&& p) {
		m_pathspec = p.m_pathspec;
		m_weight = p.m_weight;
		p.m_pathspec = nullptr;
	}
	unsigned match(const std::filesystem::path &path) const {
		if (git_pathspec_matches_path(m_pathspec, GIT_PATHSPEC_DEFAULT, path.c_str()) == 1)
			return m_weight;
		return 0;
	}
private:
	git_pathspec *m_pathspec;
	unsigned m_weight;

	unsigned pattern_weight(const std::string &pattern) {
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
};

}

#endif
