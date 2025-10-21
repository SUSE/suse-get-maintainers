#include <chrono>
#include <fstream>
#include <vector>
#include <regex>
#include <cstdlib>
#include <filesystem>

#include <getopt.h>
#include <sys/stat.h>
#include <utime.h>

#include "helpers.h"
#include "git2.h"
#include "cves.h"
#include "curl.h"
#include "cve2bugzilla.h"

namespace {
	void usage(const char *prog, std::ostream &os);
	template<bool> std::vector<std::string> read_patch_sans_new_lines(std::istream &);
	std::string get_hash(const std::vector<std::string> &, long&);
	long get_references_idx(const std::vector<std::string> &);
	bool already_has_cve_ref(const std::string&, const std::string&);
	bool already_has_bsc_ref(const std::string&, const std::string&);
	void parse_options(int argc, char **argv);
	struct gm {
		std::filesystem::path vulns;
		std::string cve_branch = "origin/master";
		std::vector<std::string> paths;
		bool init = false;
	} gm;

}

int main(int argc, char **argv)
{
	SGM_BEGIN;

	parse_options(argc, argv);

	if (gm.paths.empty() && (!gm.init || gm.vulns.empty()))
		fail_with_message("You must provide at least one patch or clone the vulns repository with --init (-i) and --vulns (-v)!  See --help (-h)!");

	LibGit2 lg2_state;
	constexpr const char cve2bugzilla_url[] = "https://gitlab.suse.de/security/cve-database/-/raw/master/data/cve2bugzilla";
	auto cve2bugzilla_file = fetch_file_if_needed({}, "cve2bugzilla.txt", cve2bugzilla_url,
						      false, false, false, std::chrono::hours{12});

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
		const auto origin_master_ref = gm.vulns / ".git/refs/remotes/origin/master";

		if (std::filesystem::exists(origin_master_ref)) {
			const auto mtime = std::filesystem::last_write_time(origin_master_ref);
			const auto now = std::filesystem::file_time_type::clock::now();
			constexpr const std::chrono::minutes expires_after{15};

			if (mtime < now - expires_after) {
				fetch_repo(gm.vulns, "origin");
				cve2bugzilla_file = fetch_file_if_needed({}, "cve2bugzilla.txt",
									 cve2bugzilla_url,
									 false, true, false,
									 std::chrono::hours{12});
			}
			std::filesystem::last_write_time(origin_master_ref, now);

		}
	}

	CVEHashMap<ShaSize::Long> cve_hash_map{gm.cve_branch, 0, false};
	if (!cve_hash_map.load(gm.vulns))
		fail_with_message("Couldn't load kernel vulns database git tree");

	CVE2Bugzilla cve_to_bugzilla;
	if (!cve_to_bugzilla.load(cve2bugzilla_file))
		fail_with_message("Couldn't load cve2bugzilla.txt");

	for (auto const &p: gm.paths) {
		const auto path_to_patch = std::filesystem::absolute(p);

		std::ifstream file(path_to_patch);
		if (!file.is_open()) {
			emit_message("Cannot open file: ", path_to_patch);
			continue;
		}

		auto lines = read_patch_sans_new_lines<false>(file);
		long sha_idx;
		const auto sha = get_hash(lines, sha_idx);
		if (sha.size() != 40 || !is_hex(sha)) {
			emit_message(path_to_patch, " has no valid Git-commit reference (", sha, ")");
			continue;
		}

		const std::string cve = cve_hash_map.get_cve(sha);
		if (cve.empty())
			continue;
		const std::string bsc = cve_to_bugzilla.get_bsc(cve);

		const long idx = get_references_idx(lines);
		if (idx == -1) {
			lines[sha_idx] += "\nReferences: " + cve;
			if (!bsc.empty())
				lines[sha_idx] += " " + bsc;
		} else {
			if (!already_has_cve_ref(lines[idx], cve))
				lines[idx] += " " + cve;
			if (!bsc.empty() && !already_has_bsc_ref(lines[idx], bsc))
				lines[idx] += " " + bsc;
		}

		std::filesystem::path new_patch{path_to_patch};
		new_patch += ".NEW";

		std::ofstream new_file(new_patch);
		if (!new_file.is_open()) {
			emit_message("Cannot open file: ", new_patch);
			continue;
		}

		for (const auto &l: lines)
			new_file << l << std::endl;

		std::filesystem::rename(new_patch, path_to_patch);
	}

	SGM_END;
}


namespace {

	void usage(const char *prog, std::ostream &os)
	{
		os << prog << " [PATH_TO_A_PATCH...]\n";
		os << "  --help, -h                 - Print this help message\n";
		os << "  --vulns, -v <path>         - Path to the clone of https://git.kernel.org/pub/scm/linux/security/vulns.git ($VULNS_GIT)\n";
		os << "  --cve_branch, -b           - Which branch do we care about in $VULNS_GIT repository (by default origin/master)\n";
		os << "  --init, -i                 - Clone the upstream vulns repository;  You need to provide at least -v!\n";
		os << "  --from_stdin, -f           - Read paths to patches from stdin instead of arguments\n";
		os << "  --ksource_git, -k          - Just process all files in $KSOURCE_GIT/patches.suse\n";
	}

	struct option opts[] = {
		{ "help", no_argument, nullptr, 'h' },
		{ "vulns", required_argument, nullptr, 'v' },
		{ "cve_branch", no_argument, nullptr, 'b' },
		{ "from_stdin", no_argument, nullptr, 'f' },
		{ "ksource_git", no_argument, nullptr, 'k' },
		{ "init", no_argument, nullptr, 'i' },
		{ nullptr, 0, nullptr, 0 },
	};

	std::vector<std::string> read_all_patches();
	void parse_options(int argc, char **argv)
	{
		int c;

		for (;;) {
			int opt_idx;

			c = getopt_long(argc, argv, "hv:b:ifk", opts, &opt_idx);
			if (c == -1)
				break;

			switch (c) {
			case 'h':
				usage(argv[0], std::cout);
				std::exit(0);
			case 'v':
				gm.vulns = optarg;
				break;
			case 'b':
				gm.cve_branch = optarg;
				break;
			case 'i':
				gm.init = true;
				break;
			case 'f':
				gm.paths = read_patch_sans_new_lines<true>(std::cin);
				break;
			case 'k':
				gm.paths = read_all_patches();
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

	bool already_has_cve_ref(const std::string &ref_line, const std::string &cve_number)
	{
		const auto git_cve_regex = std::regex(cve_number, std::regex::optimize | std::regex::icase);
		return std::regex_search(ref_line, git_cve_regex);
	}

	bool already_has_bsc_ref(const std::string &ref_line, const std::string &bsc_number)
	{
		return ref_line.find(bsc_number) != std::string::npos;
	}

	template<bool trim> std::vector<std::string> read_patch_sans_new_lines(std::istream &f)
	{
		std::vector<std::string> ret;

		for (std::string line; std::getline(f, line);)
			if constexpr (trim)
				ret.push_back(strip(line));
			else
				ret.push_back(line);

		return ret;
	}

	std::vector<std::string> read_all_patches()
	{
		std::string ksource_git;
		try_to_fetch_env(ksource_git, "KSOURCE_GIT");
		if (ksource_git.empty())
			fail_with_message("Please set KSOURCE_GIT!");
		ksource_git += "/patches.suse";
		if (!std::filesystem::exists(ksource_git))
			fail_with_message(ksource_git + " does not exists!");

		std::vector<std::string> ret;

		try {
			for (const auto &entry: std::filesystem::directory_iterator(ksource_git))
				ret.push_back(entry.path());
		} catch (...) {
			fail_with_message(ksource_git + " cannot be read!");
		}

		return ret;
	}
}
