#ifndef SGM_CVE_HASH_MAP_H
#define SGM_CVE_HASH_MAP_H

#include <unordered_map>
#include <set>
#include <vector>
#include <algorithm>
#include <string>
#include <sstream>
#include "git2.h"

namespace {
	enum struct ShaSize
	{
		Long,
		Short
	};

	template<ShaSize S>
	struct CVEHashMap : NonCopyable {
		CVEHashMap(const std::string &b, unsigned y, bool r) : branch(b), year(y), rejected(r) {}

		bool load(const std::string &vsource)
			{
				if (vsource.empty())
					return false;

				auto vulns_repo = SlGit::Repo::open(vsource);
				if (!vulns_repo)
					fail_with_message("Unable to open vulns.git at ", vsource, " ;", git_error_last()->message);

				const std::string error_message = "Unable to load vulns.git tree for ";

				auto commit = vulns_repo->commitRevparseSingle(branch);
				if (!commit)
					fail_with_message(error_message, branch, "; ", git_error_last()->message);

				const std::string cve_prefix = rejected ? "cve/rejected/" : "cve/published/";

				const auto regex_sha1_file = year
					? std::regex(cve_prefix + std::to_string(year) + "/.*sha1", std::regex::optimize)
					: std::regex(cve_prefix + ".*sha1", std::regex::optimize);

				Files files;
				if (files.from_tree_filtered(*commit->tree(), regex_sha1_file))
					fail_with_message(error_message, branch, "; ", git_error_last()->message);

				if (files.empty() && year)
					throw 0;

				const auto contentsOpt = files.file_contents(*vulns_repo);
				if (!contentsOpt)
					fail_with_message(error_message, branch, "; ", git_error_last()->message);

				const auto regex_cve_number = std::regex("CVE-[0-9][0-9][0-9][0-9]-[0-9]+", std::regex::optimize);
				for (const auto &[file, contents]: *contentsOpt) {
					std::smatch match;
					std::regex_search(file, match, regex_cve_number);
					std::string cve_number = match.str();
					if (cve_number.size() < 10) {
						emit_message(cve_number, " doesn't seem to be a cve number!");
						continue;
					}
					std::istringstream iss(contents);
					std::string sha_hash;
					while (iss >> sha_hash) {
						if (!is_hex(sha_hash) || sha_hash.size() != 40) {
							emit_message('"', sha_hash, "\" doesn't seem to be a commit hash! (from a file \"", file, "\")");
							continue;
						}
						if constexpr (ShaSize::Short == S)
							m_sha_hash_map.insert(std::make_pair(sha_hash.substr(0, 12), cve_number));
						else {
							m_cve_hash_multimap.insert(std::make_pair(cve_number, sha_hash));
							m_sha_hash_map.insert(std::make_pair(std::move(sha_hash), cve_number));
						}
					}
				}
				return true;
			}

		std::string get_cve(const std::string &sha_commit) const
			{
				const auto it = m_sha_hash_map.find(sha_commit);
				if (it != m_sha_hash_map.cend())
					return it->second;

				return std::string();
			}

		std::vector<std::string> get_shas(const std::string &cve_number) const requires (S == ShaSize::Long)
			{
				std::vector<std::string> ret;
				const auto range = m_cve_hash_multimap.equal_range(cve_number);
				for (auto it = range.first; it != range.second; ++it)
					ret.push_back(it->second);
				return ret;
			}

		std::set<std::string> get_all_cves() const requires (S == ShaSize::Long)
			{
				std::set<std::string> ret;
				std::transform(m_cve_hash_multimap.cbegin(), m_cve_hash_multimap.cend(), std::inserter(ret, ret.end()), [](const auto &p) { return p.first; });
				return ret;
			}
	private:
		std::unordered_multimap<std::string, std::string> m_cve_hash_multimap;
		std::unordered_map<std::string, std::string> m_sha_hash_map;
		std::string branch;
		unsigned year;
		bool rejected;
	};

}
#endif
