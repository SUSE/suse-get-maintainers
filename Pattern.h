#ifndef SGM_PATTERN_H
#define SGM_PATTERN_H

#include <filesystem>
#include <optional>
#include <string>

#include <sl/git/PathSpec.h>

namespace SGM {

struct Pattern {
	Pattern() = delete;

	unsigned match(const std::filesystem::path &path) const {
		if (m_pathspec.matchesPath(path))
			return m_weight;
		return 0;
	}

	static std::optional<Pattern> create(const std::string_view &p);
private:
	SlGit::PathSpec m_pathspec;
	unsigned m_weight;

	Pattern(SlGit::PathSpec pathspec, unsigned weight) : m_pathspec(std::move(pathspec)),
		m_weight(weight) {}

	static constexpr unsigned pattern_weight(const std::string &pattern);
};

}

#endif
