#ifndef SGM_PATTERN_H
#define SGM_PATTERN_H

#include <filesystem>
#include <optional>
#include <string>

#include <git2.h>

namespace SGM {

struct Pattern {
	Pattern() = delete;
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

	static std::optional<Pattern> create(const std::string_view &p);
private:
	git_pathspec *m_pathspec;
	unsigned m_weight;

	Pattern(git_pathspec *pathspec, unsigned weight) : m_pathspec(pathspec), m_weight(weight) {}

	static constexpr unsigned pattern_weight(const std::string &pattern);
};

}

#endif
