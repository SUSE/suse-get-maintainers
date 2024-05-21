#include <fstream>
#include <vector>
#include <regex>
#include <cstdio>
#include <cstdlib>
#include <ctime>

#include <getopt.h>
#include <sys/stat.h>
#include <utime.h>

#include "helpers.h"
#include "git2.h"
#include "cves.h"

namespace {
	void usage(const char *prog, std::ostream &os);
	std::vector<std::string> read_patch_sans_new_lines(std::istream &, bool);
	std::string get_hash(const std::vector<std::string> &, long&);
	long get_references_idx(const std::vector<std::string> &);
	bool already_has_reference(const std::string&, const std::string&);
	void parse_options(int argc, char **argv);
	struct gm {
		gm() : init(false) {}
		std::string vulns;
		std::vector<std::string> paths;
		bool init;
	} gm;

}

int main(int argc, char **argv)
{
	SGM_BEGIN;

	parse_options(argc, argv);

	if (gm.paths.empty() && (!gm.init || gm.vulns.empty()))
		fail_with_message("You must provide at least one patch or clone the vulns repository with --init (-i) and --vulns (-v)!  See --help (-h)!");

	LibGit2 lg2_state;

	if (gm.init) {
		if (!gm.vulns.empty()) {
			Repo repo;
			if (repo.clone(gm.vulns, "https://git.kernel.org/pub/scm/linux/security/vulns.git"))
				fail_with_message(git_error_last()->message);
			emit_message("\n\nexport VULNS_GIT=\"", gm.vulns, "\" # store into ~/.bashrc\n\n");
		}
		return 0;
	}

	if (gm.vulns.empty()) {
		const char *vulns_tree_dir = std::getenv("VULNS_GIT");
		if (vulns_tree_dir)
			gm.vulns = vulns_tree_dir;
		else
			fail_with_message("Provide a path to kernel vulns database git tree either via -v or $VULNS_GIT");
	}

	{
		constexpr const char origin_master_file[] = "/.git/refs/remotes/origin/master";
		const std::string origin_master_ref = gm.vulns + origin_master_file;

		struct stat sb;
		if (stat(origin_master_ref.c_str(), &sb) == 0) {
			struct timespec current_time;
			timespec_get(&current_time, TIME_UTC);

			constexpr decltype(current_time.tv_sec) expires_after_seconds = 60 * 15;
			decltype(current_time.tv_sec) time_diff = current_time.tv_sec - sb.st_mtim.tv_sec;
			if (time_diff > expires_after_seconds)
				fetch_repo(gm.vulns, "origin");
			struct utimbuf t;
			t.modtime = current_time.tv_sec;
			utime(origin_master_ref.c_str(), &t);
		}
	}

	CVEHashMap cve_hash_map{0, false};
	if (!cve_hash_map.load(gm.vulns))
		fail_with_message("Couldn't load kernel vulns database git tree");

	for (auto const &p: gm.paths) {
		std::string path_to_patch;
		if (!p.empty() && p[0] != '/') {
			const char *pwd = std::getenv("PWD");
			if (pwd)
				path_to_patch = std::string(pwd) + "/" + p;
		} else
			path_to_patch = p;

		std::ifstream file(path_to_patch);
		if (!file.is_open()) {
			emit_message("Cannot open file: ", path_to_patch);
			continue;
		}

		auto lines = read_patch_sans_new_lines(file, false);
		long sha_idx;
		const auto sha = get_hash(lines, sha_idx);
		if (sha.size() != 40 && !is_hex(sha)) {
			emit_message(path_to_patch, " has no valid Git-commit reference (", sha, ")");
			continue;
		}

		const std::string cve = cve_hash_map.get_cve(sha);
		if (cve.empty())
			continue;

		const long idx = get_references_idx(lines);
		if (idx == -1) {
			const std::string update = lines[sha_idx] + "\nReferences: " + cve;
			lines[sha_idx] = update;
		} else {
			if (already_has_reference(lines[idx], cve))
				continue;

			const std::string update = lines[idx] + " " + cve;
			lines[idx] = update;
		}

		std::string new_patch = path_to_patch;
		new_patch += ".NEW";

		std::ofstream new_file(new_patch);
		if (!new_file.is_open()) {
			emit_message("Cannot open file: ", new_patch);
			continue;
		}

		for (const auto &l: lines)
			new_file << l << std::endl;

		rename(new_patch.c_str(), path_to_patch.c_str());
	}

	SGM_END;
}


namespace {

	void usage(const char *prog, std::ostream &os)
	{
		os << prog << std::endl;
		os << "  --help, -h                 - Print this help message" << std::endl;
		os << "  --vulns, -v <path>         - Path to the clone of https://git.kernel.org/pub/scm/linux/security/vulns.git ($VULNS_GIT)" << std::endl;
		os << "  --init, -i                 - Clone the upstream vulns repository;  You need to provide at least -v!" << std::endl;
		os << "  --from_stdin, -f           - Read paths to patches from stdin instead of arguments" << std::endl;
	}

	struct option opts[] = {
		{ "help", no_argument, nullptr, 'h' },
		{ "vulns", required_argument, nullptr, 'v' },
		{ "from_stdin", no_argument, nullptr, 'f' },
		{ "init", no_argument, nullptr, 'i' },
		{ nullptr, 0, nullptr, 0 },
	};

	void parse_options(int argc, char **argv)
	{
		int c;

		for (;;) {
			int opt_idx;

			c = getopt_long(argc, argv, "hv:if", opts, &opt_idx);
			if (c == -1)
				break;

			switch (c) {
			case 'h':
				usage(argv[0], std::cout);
				std::exit(0);
			case 'v':
				gm.vulns = optarg;
				break;
			case 'i':
				gm.init = true;
				break;
			case 'f':
				gm.paths = read_patch_sans_new_lines(std::cin, true);
				break;
			default:
				usage(argv[0], std::cerr);
				throw 1;
			}
		}

		for (int i = optind; i < argc; ++i)
			gm.paths.emplace_back(argv[i]);
	}

	std::string strip(const std::string &line)
	{
		static constexpr const char *spaces = " \n\t\r";
		const auto pos1 = line.find_first_not_of(spaces);
		const auto pos2 = line.find_last_not_of(spaces);

		if (pos1 == std::string::npos)
			return std::string("");

		return line.substr(pos1, pos2-pos1+1);
	}

	std::string get_hash(const std::vector<std::string> &v, long &idx)
	{
		thread_local const auto git_commit_regex = std::regex("Git-commit: ([0-9a-fA-F]+)", std::regex::optimize);
		std::smatch match;
		idx = 0;
		for (const auto &line: v) {
			if (std::regex_search(line, match, git_commit_regex))
				return strip(match.str(1));
			++idx;
		}

		return std::string();
	}

	long get_references_idx(const std::vector<std::string> &v)
	{
		thread_local const auto git_ref_regex = std::regex("References: ", std::regex::optimize | std::regex::icase);
		long i = 0;
		for (const auto &line: v) {
			if (std::regex_search(line, git_ref_regex))
				return i;
			++i;
		}
		return -1;
	}

	bool already_has_reference(const std::string &ref_line, const std::string &cve_number)
	{
		const auto git_cve_regex = std::regex(cve_number, std::regex::optimize | std::regex::icase);
		return std::regex_search(ref_line, git_cve_regex);
	}

	std::vector<std::string> read_patch_sans_new_lines(std::istream &f, bool trim)
	{
		std::vector<std::string> ret;

		for (std::string line; std::getline(f, line);)
			if(trim)
				ret.push_back(strip(line));
			else
				ret.push_back(line);

		return ret;
	}
}
