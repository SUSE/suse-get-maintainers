#ifndef SGM_MAINTAINERS_H
#define SGM_MAINTAINERS_H

#include <string>
#include <vector>
#include <fstream>
#include <sstream>

#include <sl/git/Repo.h>
#include <sl/helpers/String.h>

#include "helpers.h"
#include "Stanza.h"

namespace SGM {

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
						if (!st.add_pattern(fpattern))
							throw 1;
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
						if (!st.add_pattern(fpattern))
							throw 1;
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
