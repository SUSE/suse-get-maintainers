#ifndef SGM_STANZA_H
#define SGM_STANZA_H

#include <filesystem>
#include <numeric>
#include <set>

#include "Pattern.h"
#include "Person.h"

#include "helpers.h"

namespace SGM {

class Stanza {
public:
	Stanza() = default;
	Stanza(const std::string &name) : m_name(name) {}
	Stanza(const std::string &n, const std::string &who) : m_name(n) {
		if (auto m = Person::parsePerson(who, Role::Maintainer))
			m_maintainers.push_back(std::move(*m));
	}

	unsigned match_path(const std::filesystem::path &path) const {
		return std::accumulate(m_patterns.cbegin(), m_patterns.cend(), 0u,
				       [&path](unsigned m, const Pattern &p) {
			return std::max(m, p.match(path));
		});
	}

	void add_maintainer_and_store(const std::string_view &maintainer,
				      std::set<std::string> &suse_users) {
		if (auto m = Person::parsePerson(maintainer, Role::Maintainer)) {
			suse_users.insert(m->email().substr(0, m->email().find_first_of("@")));
			// TODO
			m->setEmail(translate_email(m->email()));
			// END TODO
			m_maintainers.push_back(std::move(*m));
		} else
			emit_message("MAINTAINERS: contact ", maintainer,
				     " cannot be parsed into name and email!");
	}

	void add_backporter(const std::string_view &maintainer, int cnt)
	{
		if (auto m = Person::parsePerson(maintainer, Role::Maintainer, cnt)) {
			// TODO
			m->setEmail(translate_email(m->email()));
			// END TODO
			m_maintainers.push_back(std::move(*m));
		} else
			emit_message("MAINTAINERS: contact ", maintainer,
				     " cannot be parsed into name and email!");
	}

	void add_maintainer_if(const std::string_view maintainer,
			       const std::set<std::string> &suse_users) {
		if (auto m = Person::parsePerson(maintainer, Role::Upstream)) {
			// TODO
			m->setEmail(translate_email(m->email()));
			// END TODO
			if (suse_users.contains(m->email().substr(0, m->email().find("@"))))
				m_maintainers.push_back(std::move(*m));
		} else
			emit_message("Upstream MAINTAINERS: contact ", maintainer,
				     " cannot be parsed into name and email!");
	}

	bool add_pattern(const std::string_view &pattern) {
		auto p = Pattern::create(pattern);
		if (!p)
			return false;
		m_patterns.push_back(std::move(*p));
		return true;
	}

	bool empty() const {
		return m_name.empty() || m_maintainers.empty() || m_patterns.empty();
	}

	template<typename F>
	void for_all_maintainers(F callback) const {
		for (const auto &p: m_maintainers)
			callback(p);
	}

	void new_entry(const std::string_view &n) {
		m_name = n;
		m_maintainers.clear();
		m_patterns.clear();
	}

	const std::string name() const { return m_name; }
private:
	std::string m_name;
	std::vector<Person> m_maintainers;
	std::vector<Pattern> m_patterns;
};

} // namespace

#endif
