#include <chrono>
#include <cxxopts.hpp>
#include <fstream>
#include <vector>
#include <regex>
#include <cstdlib>
#include <filesystem>

#include <getopt.h>
#include <sys/stat.h>
#include <utime.h>

#include <sl/curl/Curl.h>
#include <sl/cves/CVEHashMap.h>
#include <sl/git/Repo.h>
#include <sl/helpers/String.h>

#include "helpers.h"
#include "cve2bugzilla.h"

namespace {

struct gm {
	std::filesystem::path vulns;
	std::string cve_branch;
	std::vector<std::string> paths;
	bool init;
} gm;

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

template<bool trim> std::vector<std::string> read_patch_sans_new_lines(std::istream &f)
{
	std::vector<std::string> ret;

	for (std::string line; std::getline(f, line);)
		if constexpr (trim)
			ret.push_back(SlHelpers::String::trim(line));
		else
			ret.push_back(line);

	return ret;
}

void parse_options(int argc, char **argv)
{
	cxxopts::Options options { argv[0], "Add CVE numbers to patches" };
	options.add_options()
		("h,help", "Print this help message")
		("v,vulns", "Path to the clone of https://git.kernel.org/pub/scm/linux/security/vulns.git "
			    "($VULNS_GIT)",
			cxxopts::value(gm.vulns))
		("b,cve_branch", "Which branch do we care about in $VULNS_GIT repository "
				 "(by default origin/master)",
			cxxopts::value(gm.cve_branch)->default_value("origin/master"))
		("i,init", "Clone the upstream vulns repository;  You need to provide at least -v!",
			cxxopts::value(gm.init)->default_value("false"))
		("f,from_stdin", "Read paths to patches from stdin instead of arguments")
		("k,ksource_git", "Just process all files in $KSOURCE_GIT/patches.suse")
		("patches", "Patches to process", cxxopts::value(gm.paths))
	;

	options.parse_positional("patches");
	options.positional_help("[PATH_TO_A_PATCH...]");

	try {
		const auto opts = options.parse(argc, argv);
		if (opts.contains("help")) {
			std::cout << options.help();
			std::exit(0);
		}
		if (opts.contains("from_stdin"))
			gm.paths = read_patch_sans_new_lines<true>(std::cin);
		if (opts.contains("ksource_git"))
			gm.paths = read_all_patches();

		if (gm.paths.empty() && (!gm.init || gm.vulns.empty()))
			fail_with_message("You must provide at least one patch or clone the vulns "
					  "repository with --init (-i) and --vulns (-v)!  "
					  "See --help (-h)!");
	} catch (const cxxopts::exceptions::parsing &e) {
		std::cerr << "arguments error: " << e.what() << '\n';
		std::cerr << options.help();
		throw 1;
	}
}

std::string get_hash(const std::vector<std::string> &v, long &idx)
{
	thread_local const auto git_commit_regex = std::regex("Git-commit: ([0-9a-fA-F]+)", std::regex::optimize);
	std::smatch match;
	idx = 0;
	for (const auto &line: v) {
		if (std::regex_search(line, match, git_commit_regex))
			return SlHelpers::String::trim(match.str(1));
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

} // namespace

int main(int argc, char **argv)
{
	SGM_BEGIN;

	parse_options(argc, argv);

	constexpr const char cve2bugzilla_url[] = "https://gitlab.suse.de/security/cve-database/-/raw/master/data/cve2bugzilla";
	auto cve2bugzilla_file = SlCurl::LibCurl::fetchFileIfNeeded("cve2bugzilla.txt",
								    cve2bugzilla_url,
								    false, false,
								    std::chrono::hours{12});

	if (gm.init) {
		if (!gm.vulns.empty()) {
			if (!SlGit::Repo::clone(gm.vulns, "https://git.kernel.org/pub/scm/linux/security/vulns.git"))
				fail_with_message(git_error_last()->message);
			emit_message("\n\nexport VULNS_GIT=", gm.vulns, " # store into ~/.bashrc\n\n");
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
				SlGit::Repo::update(gm.vulns);
				cve2bugzilla_file = SlCurl::LibCurl::fetchFileIfNeeded("cve2bugzilla.txt",
									 cve2bugzilla_url,
									 true, false,
									 std::chrono::hours{12});
			}
			std::filesystem::last_write_time(origin_master_ref, now);

		}
	}

	SlCVEs::CVEHashMap cve_hash_map{SlCVEs::CVEHashMap::ShaSize::Long, gm.cve_branch, 0, false};
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
		if (sha.size() != 40 || !SlHelpers::String::isHex(sha)) {
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

