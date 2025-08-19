#ifndef SGM_MAINTAINERS_H
#define SGM_MAINTAINERS_H

#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <numeric>
#include <git2.h>

#include "helpers.h"

namespace {
	struct Pattern {
		Pattern(std::string pattern)
			{
				m_weight = pattern_weight(pattern);
				if (!pattern.empty() && pattern.back() == '/' && pattern.find_first_of('*') != std::string::npos)
					pattern.push_back('*');
				const char *ptr = pattern.c_str();
				const git_strarray array{.strings=const_cast<char **>(&ptr), .count=1};
				if (git_pathspec_new(&m_pathspec, &array))
					fail_with_message(git_error_last()->message);
			}
		~Pattern() { git_pathspec_free(m_pathspec); }
		Pattern& operator=(const Pattern&) = delete;
		Pattern(const Pattern&) = delete;
		Pattern& operator=(Pattern&& p) = delete;
		Pattern(Pattern&& p)
			{
				m_pathspec = p.m_pathspec;
				m_weight = p.m_weight;
				p.m_pathspec = nullptr;
			}
		unsigned match(const std::string &path) const
			{
				if (git_pathspec_matches_path(m_pathspec, GIT_PATHSPEC_DEFAULT, path.c_str()) == 1)
					return m_weight;
				return 0;
			}
	private:
		git_pathspec *m_pathspec;
		unsigned m_weight;

		unsigned pattern_weight(const std::string &pattern)
			{
				unsigned ret = 1, idx = 0;
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
					++idx;
				}
				return ret;
			}
	};

	struct Stanza {
		unsigned match_path(const std::string &path) const
			{
				return std::accumulate(m_patterns.cbegin(), m_patterns.cend(), 0u,
						       [&path](unsigned m, const Pattern &p) { return std::max(m, p.match(path)); });
			}
		void add_maintainer(const std::string &maintainer, std::set<std::string> &suse_users)
			{
				Person m{Role::Maintainer};
				if (parse_person(maintainer, m.name, m.email)) {
					suse_users.insert(m.email.substr(0, m.email.find_first_of("@")));
					m_maintainers.push_back(std::move(m));
				} else
					emit_message("MAINTAINERS: contact ", maintainer, " cannot be parsed into name and email!");
			}
		void add_pattern(const std::string &pattern) { m_patterns.push_back(Pattern(pattern)); }
		bool empty() const
			{
				return name.empty() || m_maintainers.empty() || m_patterns.empty();
			}
		void for_all_maintainers(std::function<void(const Person &)> callback) const
			{
				for (const auto &p: m_maintainers)
					callback(p);
			}
		Stanza(const std::string &n, const std::string &who) : name(n)
			{
				Person m{Role::Maintainer};
				if (parse_person(who, m.name, m.email))
					m_maintainers.push_back(std::move(m));
			}
		Stanza() = default;
		std::string name;
	private:
		std::vector<Person> m_maintainers;
		std::vector<Pattern> m_patterns;
	};

	void process_maitainers_file(std::vector<Stanza> &maintainers, std::set<std::string> &suse_users, const std::vector<std::string> lines)
	{
		Stanza st;
		for (const auto &s: lines) {
			if (s[1] == ':') {
				if (s[0] == 'M')
					st.add_maintainer(s, suse_users);
				else if (s[0] == 'F') {
					std::string fpattern = trim(s.substr(2));
					if (fpattern.empty())
						emit_message("MAINTAINERS entry: ", s);
					else
						st.add_pattern(std::move(fpattern));
				}
			} else {
				if (!st.empty())
					maintainers.push_back(std::move(st));
				st.name = s;
			}
		}
		if (!st.empty())
			maintainers.push_back(std::move(st));

	}

	void load_maintainers_file(std::vector<Stanza> &maintainers, std::set<std::string> &suse_users, const std::string &filename)
	{
		std::ifstream file{filename};

		if (!file.is_open())
			fail_with_message("Unable to open MAINTAINERS file: ", filename);

		std::vector<std::string> lines;
		for (std::string line; getline(file, line);) {
			std::string tmp = trim(line);
			if (tmp.size() < 2)
				continue;
			lines.push_back(std::move(tmp));
		}

		if (lines.empty())
			fail_with_message(filename, " appears to be empty");
		else
			process_maitainers_file(maintainers, suse_users, lines);
	}
}

#endif
