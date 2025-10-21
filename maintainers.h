#ifndef SGM_MAINTAINERS_H
#define SGM_MAINTAINERS_H

#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <numeric>

#include <sl/git/Repo.h>
#include <sl/helpers/String.h>

#include "helpers.h"

namespace {
	struct Pattern : NonCopyable {
		Pattern(std::string_view p)
			{
				std::string pattern{p};
				m_weight = pattern_weight(pattern);
				if (!pattern.empty() && pattern.back() == '/' && pattern.find_first_of('*') != std::string::npos)
					pattern.push_back('*');
				const char *ptr = pattern.c_str();
				const git_strarray array{.strings=const_cast<char **>(&ptr), .count=1};
				if (git_pathspec_new(&m_pathspec, &array))
					fail_with_message(git_error_last()->message);
			}
		~Pattern() { git_pathspec_free(m_pathspec); }
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

	struct Stanza {
		unsigned match_path(const std::string &path) const
			{
				return std::accumulate(m_patterns.cbegin(), m_patterns.cend(), 0u,
						       [&path](unsigned m, const Pattern &p) { return std::max(m, p.match(path)); });
			}
		void add_maintainer_and_store(const std::string_view maintainer, std::set<std::string> &suse_users)
			{
				Person m{Role::Maintainer};
				if (parse_person(maintainer, m.name, m.email)) {
					suse_users.insert(m.email.substr(0, m.email.find_first_of("@")));
					// TODO
					m.email = translate_email(m.email);
					// END TODO
					m_maintainers.push_back(std::move(m));
				} else
					emit_message("MAINTAINERS: contact ", maintainer, " cannot be parsed into name and email!");
			}
		void add_backporter(const std::string_view maintainer, int cnt)
			{
				Person m{Role::Maintainer};
				m.count = cnt;
				if (parse_person(maintainer, m.name, m.email)) {
					// TODO
					m.email = translate_email(m.email);
					// END TODO
					m_maintainers.push_back(std::move(m));
				} else
					emit_message("MAINTAINERS: contact ", maintainer, " cannot be parsed into name and email!");
			}
		void add_maintainer_if(const std::string_view maintainer, const std::set<std::string> &suse_users)
			{
				Person m{Role::Upstream};
				if (parse_person(maintainer, m.name, m.email)) {
					// TODO
					m.email = translate_email(m.email);
					// END TODO
					if (suse_users.contains(m.email.substr(0, m.email.find("@"))))
						m_maintainers.push_back(std::move(m));
				} else
					emit_message("Upstream MAINTAINERS: contact ", maintainer, " cannot be parsed into name and email!");
			}
		void add_pattern(const std::string_view pattern) { m_patterns.push_back(Pattern(pattern)); }
		bool empty() const
			{
				return name.empty() || m_maintainers.empty() || m_patterns.empty();
			}
		template<typename F>
		void for_all_maintainers(F callback) const
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
		void new_entry(const std::string_view n) { name = n; m_maintainers.clear(); m_patterns.clear(); }
		std::string name;
	private:
		std::vector<Person> m_maintainers;
		std::vector<Pattern> m_patterns;
	};

	void load_maintainers_file(std::vector<Stanza> &maintainers, std::set<std::string> &suse_users, const std::string &filename)
	{
		std::ifstream file{filename};

		if (!file.is_open())
			fail_with_message("Unable to open MAINTAINERS file: ", filename);

		Stanza st;
		for (std::string line; getline(file, line);) {
			const auto tmp = SlHelpers::String::trim(line);
			if (tmp.size() < 2)
				continue;
			if (tmp[1] == ':') {
				if (tmp[0] == 'M')
					st.add_maintainer_and_store(tmp, suse_users);
				else if (tmp[0] == 'F') {
					const auto fpattern = SlHelpers::String::trim(tmp.substr(2));
					if (fpattern.empty())
						emit_message("MAINTAINERS entry: ", tmp);
					else
						st.add_pattern(fpattern);
				}
			} else {
				if (!st.empty())
					maintainers.push_back(std::move(st));
				st.new_entry(tmp);
			}
		}
		if (!st.empty())
			maintainers.push_back(std::move(st));

		if (maintainers.empty())
			fail_with_message(filename, " appears to be empty");
	}

	void load_upstream_maintainers_file(std::vector<Stanza> &stanzas, const std::set<std::string> &suse_users, const std::string &lsource, const std::string &origin)
	{
		auto linux_repo = SlGit::Repo::open(lsource);
		if (!linux_repo)
			fail_with_message("Unable to open linux.git at ", lsource, " ;", git_error_last()->message);

		const std::string error_message = "Unable to load linux.git tree for " + origin + "/master; ";

		auto maintOpt = linux_repo->catFile(origin + "/master", "MAINTAINERS");
		if (!maintOpt)
			fail_with_message(error_message, git_error_last()->message);

		std::istringstream upstream_maintainters_file(*maintOpt);
		Stanza st;
		bool skip = true;
		for (std::string line; getline(upstream_maintainters_file, line); ) {
			if (skip) {
				if (line.starts_with("Maintainers List"))
					skip = false;
				continue;
			}
			if (line == "THE REST")
				break;
			if (line.size() < 3 || std::strchr("\t .-", line[1]))
				continue;
			if (line[1] == ':')
				switch(line[0]) {
				case 'L': // TODO?
				case 'S':
				case 'W':
				case 'Q':
				case 'B':
				case 'C':
				case 'P':
				case 'T':
				case 'X':
				case 'N': // TODO, huh?
				case 'K':
					break;
				case 'M':
				case 'R':
					st.add_maintainer_if(line, suse_users);
					break;
				case 'F':
					const auto fpattern = SlHelpers::String::trim(std::string_view(line).substr(2));
					if (fpattern.empty())
						emit_message("Upstream MAINTAINERS entry: ", line);
					else
						st.add_pattern(fpattern);
					break;
				}
			else {
				if (!st.empty())
					stanzas.push_back(std::move(st));
				st.new_entry("Upstream: " + line);
			}
		}
		if (!st.empty())
			stanzas.push_back(std::move(st));
		if (stanzas.empty())
			fail_with_message("Upstream MAINTAINERS appears to be empty");
	}
}

#endif
