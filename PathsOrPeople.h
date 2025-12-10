#pragma once

#include <filesystem>
#include <set>
#include <variant>

#include "Stanza.h"

namespace SGM {

class PathsOrPeople {
public:
	using Paths = std::set<std::filesystem::path>;

	PathsOrPeople() = delete;
	PathsOrPeople(Paths paths) : m_pop(std::move(paths)) { }
	PathsOrPeople(Stanza::Maintainers people) : m_pop(std::move(people)) { }

	bool holdsPeople() const {
		return std::holds_alternative<Stanza::Maintainers>(m_pop);
	}
	bool holdsPaths() const {
		return std::holds_alternative<Paths>(m_pop);
	}

	const Stanza::Maintainers &people() const {
		return std::get<Stanza::Maintainers>(m_pop);
	}
	const Paths &paths() const {
		return std::get<Paths>(m_pop);
	}

	std::optional<std::reference_wrapper<const Stanza::Maintainers>> peopleOpt() const {
		if (auto p = std::get_if<Stanza::Maintainers>(&m_pop))
			return std::cref(*p);
		return std::nullopt;
	}
	std::optional<std::reference_wrapper<const Paths>> pathsOpt() const {
		if (auto p = std::get_if<Paths>(&m_pop))
			return std::cref(*p);
		return std::nullopt;
	}
private:
	std::variant<Paths, Stanza::Maintainers> m_pop;
};

}
