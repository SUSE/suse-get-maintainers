#include <fstream>

#include "Maintainers.h"

using namespace SGM;

bool Maintainers::loadSUSE(const std::filesystem::path &filename,
			   const Stanza::TranslateEmail &translateEmail)
{
	std::ifstream file{filename};

	if (!file.is_open()) {
		std::cerr << "Unable to open MAINTAINERS file: " << filename << '\n';
		return false;
	}

	Stanza st;
	for (std::string line; getline(file, line);) {
		const auto tmp = SlHelpers::String::trim(line);
		if (tmp.size() < 2)
			continue;
		if (tmp[1] == ':') {
			if (tmp[0] == 'M')
				st.add_maintainer_and_store(tmp, m_suse_users, translateEmail);
			else if (tmp[0] == 'F') {
				const auto fpattern = SlHelpers::String::trim(tmp.substr(2));
				if (fpattern.empty())
					std::cerr <<  "MAINTAINERS entry: " << tmp << '\n';
				else
					st.add_pattern(fpattern);
			}
		} else {
			if (!st.empty())
				m_maintainers.push_back(std::move(st));
			st.new_entry(tmp);
		}
	}
	if (!st.empty())
		m_maintainers.push_back(std::move(st));

	if (m_maintainers.empty()) {
		std::cerr << filename << " appears to be empty" << '\n';
		return false;
	}

	return true;
}

bool Maintainers::loadUpstream(const std::filesystem::path &lsource, const std::string &origin,
			       const Stanza::TranslateEmail &translateEmail)
{
	auto linux_repo = SlGit::Repo::open(lsource);
	if (!linux_repo) {
		std::cerr << "Unable to open linux.git at " << lsource << " ;" <<
			     git_error_last()->message << '\n';
		return false;
	}

	auto maintOpt = linux_repo->catFile(origin + "/master", "MAINTAINERS");
	if (!maintOpt) {
		std::cerr << "Unable to load linux.git tree for " << origin << "/master; " <<
			     git_error_last()->message << '\n';
		return false;
	}

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
				st.add_maintainer_if(line, m_suse_users, translateEmail);
				break;
			case 'F':
				const auto fpattern = SlHelpers::String::trim(std::string_view(line).substr(2));
				if (fpattern.empty())
					std::cerr << "Upstream MAINTAINERS entry: " << line << '\n';
				else
					st.add_pattern(fpattern);
				break;
			}
		else {
			if (!st.empty())
				m_upstream_maintainers.push_back(std::move(st));
			st.new_entry("Upstream: " + line);
		}
	}
	if (!st.empty())
		m_upstream_maintainers.push_back(std::move(st));
	if (m_upstream_maintainers.empty()) {
		std::cerr << "Upstream MAINTAINERS appears to be empty\n";
		return false;
	}
	return true;
}

const Stanza *Maintainers::findBestMatchInMaintainers(const MaintainersType &sl,
						      const std::set<std::filesystem::path> &paths)
{
	const Stanza *ret = nullptr;
	unsigned best_weight = 0;
	for(const auto &s: sl) {
		unsigned weight = 0;
		for (const auto &path: paths)
			weight += s.match_path(path);
		if (weight > best_weight) {
			ret = &s;
			best_weight = weight;
		}
	}
	return ret;
}
