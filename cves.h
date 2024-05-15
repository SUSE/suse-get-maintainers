#ifndef SGM_CVE_HASH_MAP_H
#define SGM_CVE_HASH_MAP_H

#include <unordered_map>
#include <set>
#include <algorithm>
#include <string>
#include <fstream>
#include <iostream>
#include "git2.h"

namespace {
	struct CVEHashMap {
		CVEHashMap(int y, bool r) : year(y), rejected(r) {}

		bool load(const std::string &vsource);
		std::string get_sha(const std::string &cve_number) const;
		std::string get_cve(const std::string &sha_commit) const;
		std::set<std::string> get_all_cves() const;
	private:
		std::unordered_map<std::string, std::string> m_cve_hash_map;
		std::unordered_map<std::string, std::string> m_sha_hash_map;
		int year;
		bool rejected;
	};

	bool CVEHashMap::load(const std::string &vsource)
	{
		Repo vulns_repo;

		if (vsource.empty())
			return false;

		if (vulns_repo.from_path(vsource))
			fail_with_message("Unable to open vulns.git at ", vsource, " ;", git_error_last()->message);

		const std::string error_message = "Unable to load vulns.git tree for origin/master; ";

		Object obj;
		if (obj.from_rev(vulns_repo, "origin/master"))
			fail_with_message(error_message, git_error_last()->message);

		Commit commit;
		if (commit.from_oid(vulns_repo, git_object_id(obj.get())))
			fail_with_message(error_message, git_error_last()->message);

		Tree commit_tree;
		if (commit_tree.from_commit(commit))
			fail_with_message(error_message, git_error_last()->message);

		const std::string cve_prefix = rejected ? "cve/rejected/" : "cve/published/";

		const auto regex_sha1_file = year
			? std::regex(cve_prefix + std::to_string(year) + "/.*sha1", std::regex::optimize)
			: std::regex(cve_prefix + ".*sha1", std::regex::optimize);

		Files files;
		if (files.from_tree_filtered(commit_tree, regex_sha1_file))
			fail_with_message(error_message, git_error_last()->message);

		if (files.m_paths.empty() && year)
			throw 0;

		FilesContents fc;
		if (fc.from_tree(commit_tree, files))
			fail_with_message(error_message, git_error_last()->message);

		const auto regex_cve_number = std::regex("CVE-[0-9][0-9][0-9][0-9]-[0-9]+", std::regex::optimize);
		for (const auto &[file, sha]: fc.m_contents) {
			const std::string_view sha_hash = trim(sha);
			if (!is_hex(sha_hash) || sha_hash.size() != 40) {
				emit_message(sha_hash, " doesn't seem to be a commit hash!");
				continue;
			}
			std::smatch match;
			std::regex_search(file, match, regex_cve_number);
			std::string cve_number = match.str();
			if (cve_number.size() < 10) {
				emit_message(cve_number, " doesn't seem to be a cve number!");
				continue;
			}
			m_cve_hash_map.insert(std::make_pair(cve_number, sha_hash));
			m_sha_hash_map.insert(std::make_pair(std::move(sha_hash), std::move(cve_number)));
		}
		return true;
	}

	std::string CVEHashMap::get_sha(const std::string &cve_number) const
	{
		const auto it = m_cve_hash_map.find(cve_number);
		if (it != m_cve_hash_map.cend())
			return it->second;

		return std::string();
	}

	std::string CVEHashMap::get_cve(const std::string &sha_commit) const
	{
		const auto it = m_sha_hash_map.find(sha_commit);
		if (it != m_sha_hash_map.cend())
			return it->second;

		return std::string();
	}

	std::set<std::string> CVEHashMap::get_all_cves() const
	{
		std::set<std::string> ret;
		std::transform(m_cve_hash_map.cbegin(), m_cve_hash_map.cend(), std::inserter(ret, ret.end()), [](const auto &p) { return p.first; });
		return ret;
	}
}
#endif
