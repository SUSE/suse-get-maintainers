#pragma once

#include <filesystem>
#include <set>
#include <variant>

#include <sl/kerncvs/Stanza.h>

namespace SGM {

class PathsOrPeople {
public:
	using Paths = std::set<std::filesystem::path>;
	using Maintainers = SlKernCVS::Stanza::Maintainers;

	PathsOrPeople() = delete;
	PathsOrPeople(Paths paths) : m_pop(std::move(paths)) { }
	PathsOrPeople(Maintainers people) : m_pop(std::move(people)) { }

	bool holdsPeople() const {
		return std::holds_alternative<Maintainers>(m_pop);
	}
	bool holdsPaths() const {
		return std::holds_alternative<Paths>(m_pop);
	}

	const Maintainers &people() const {
		return std::get<Maintainers>(m_pop);
	}
	const Paths &paths() const {
		return std::get<Paths>(m_pop);
	}

	std::optional<std::reference_wrapper<const Maintainers>> peopleOpt() const {
		if (auto p = std::get_if<Maintainers>(&m_pop))
			return std::cref(*p);
		return std::nullopt;
	}
	std::optional<std::reference_wrapper<const Paths>> pathsOpt() const {
		if (auto p = std::get_if<Paths>(&m_pop))
			return std::cref(*p);
		return std::nullopt;
	}
private:
	std::variant<Paths, Maintainers> m_pop;
};

}
