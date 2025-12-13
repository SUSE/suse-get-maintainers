#include <cxxopts.hpp>
#include <fstream>
#include <string>
#include <set>
#include <optional>
#include <cstdio>
#include <unistd.h>
#include <filesystem>

#include <sys/resource.h>

#include <sl/curl/Curl.h>
#include <sl/cves/CVE2Bugzilla.h>
#include <sl/cves/CVEHashMap.h>
#include <sl/git/Git.h>
#include <sl/helpers/Color.h>
#include <sl/helpers/Misc.h>
#include <sl/helpers/SUSE.h>
#include <sl/kerncvs/Maintainers.h>
#include <sl/kerncvs/Person.h>
#include <sl/sqlite/SQLConn.h>

#include "GitHelpers.h"
#include "OutputFormatter.h"
#include "PathsOrPeople.h"

using namespace SGM;
using Clr = SlHelpers::Color;

namespace {

template<typename... Args> void fail_with_message(Args&&... args)
{
	(std::cerr << ... << args) << std::endl;
	throw 1;
}

class SQLConn : public SlSqlite::SQLConn {
public:
	virtual bool prepDB() override {
		if (!prepareStatement("SELECT user.email, sum(map.count) AS cnt "
				     "FROM user_file_map AS map "
				     "LEFT JOIN user ON map.user = user.id "
				     "WHERE map.file = (SELECT id FROM file WHERE file = :file "
				     "AND dir = (SELECT id FROM dir WHERE dir = :dir)) "
				     "GROUP BY substr(user.email, 0, instr(user.email, '@')) "
				     "ORDER BY cnt DESC, user.email "
				     "LIMIT :limit;", selGetMaintainers))
			return false;

		return true;
	}

	std::optional<SlSqlite::SQLConn::SelectResult>
	get_maintainers(const std::string &file, const std::string &dir, int limit) const
	{
		return select(selGetMaintainers, {
				{ ":file", file },
				{ ":dir", dir },
				{ ":limit", limit },
				}, { typeid(std::string), typeid(int) });
	}

	explicit operator bool() const { return sqlHolder.operator bool(); }
private:
	SlSqlite::SQLStmtHolder selGetMaintainers;
};

struct gm {
	std::filesystem::path cacheDir;
	std::filesystem::path maintainers;
	std::filesystem::path kernel_tree;
	std::string origin;
	std::string cve_branch;
	std::set<std::string> shas;
	std::set<std::filesystem::path> paths;
	std::set<std::filesystem::path> diffs;
	std::set<std::string> cves;
	std::filesystem::path vulns;
	std::string whois;
	std::string grep;
	std::string fixes;
	std::filesystem::path conf_file_map;
	unsigned int year;
	bool skipSUSE;
	bool skipUpstream;
	bool rejected;
	bool all_cves;
	bool json;
	bool csv;
	bool names;
	bool trace;
	bool refresh;
	bool init;
	bool no_translation;
	bool only_maintainers;
	bool no_db;
	bool colors;
	bool grep_names_only;

	bool from_stdin;
} gm;

constexpr std::size_t tracking_fixes_opened_files = 64;
constexpr std::size_t min_total_opened_files = 80;
constexpr std::size_t libgit2_opened_files_factor = 2;
static_assert(min_total_opened_files >= tracking_fixes_opened_files + libgit2_opened_files_factor);

std::size_t get_soft_limit_for_opened_files(std::size_t min_limit)
{
	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
		if (rl.rlim_cur < min_limit)
			fail_with_message("RLIMIT_NOFILE is less than ", min_limit, ".  Please bump it!");
		return rl.rlim_cur;
	}
	Clr(std::cerr, Clr::YELLOW) << "getrlimit() failed: " << strerror(errno);
	return 1024;
}

// TODO
#include <unordered_map>
std::unordered_map<std::string, std::string> translation_table;
bool do_not_translate = false;

bool load_temporary(std::unordered_map<std::string, std::string> &h,
		    const std::filesystem::path &filename)
{
	std::ifstream file{filename};

	if (!file.is_open())
		std::cerr << "Unable to open user-bugzilla-map.txt file: " << filename << '\n';

	for (std::string line; getline(file, line);) {
		if (line.empty() || line[0] == ';' || line[0] == ' ')
			continue;
		const auto equal_sign_idx = line.find_first_of("=");
		if (equal_sign_idx == std::string::npos) {
			std::cerr << "user-bugzilla-map.txt: " << line << '\n';
			continue;
		}
		const auto user = SlHelpers::String::trim(std::string_view(line).substr(0, equal_sign_idx));
		const auto bz_user = SlHelpers::String::trim(std::string_view(line).substr(equal_sign_idx + 1));
		if (user.empty() || bz_user.empty()) {
			std::cerr << "user-bugzilla-map.txt: " << line << '\n';
			continue;
		}
		h.insert(std::make_pair(user, bz_user));
	}

	return true;
}

std::string translateEmail(const std::string_view &sv)
{
	if (do_not_translate || sv.starts_with("kernel-cvs@") || sv.starts_with("kernel@"))
		return std::string(sv);
	const std::string key = std::string(sv.substr(0, sv.find("@")));
	const auto it = translation_table.find(key);
	if (it != translation_table.cend()) {
		if (it->second.find("@") == std::string::npos)
			return it->second + "@suse.com";
		return it->second;
	}
	return key + "@suse.com";
}
// END TODO

template <typename T>
void moveVecToSet(const std::vector<T> &vec, std::set<T> &set) {
	set.insert(std::make_move_iterator(vec.begin()), std::make_move_iterator(vec.end()));
}

void parse_options(int argc, char **argv)
{
	cxxopts::Options options { argv[0],
				"(version: " SUSE_GET_MAINTAINERS_VERSION ") For more information, read the man page.\n" };
	std::vector<decltype(gm.shas)::key_type> shas;
	std::vector<decltype(gm.paths)::key_type> paths;
	std::vector<decltype(gm.diffs)::key_type> diffs;
	std::vector<decltype(gm.cves)::key_type> cves;
	options.add_options()
		("h,help", "Print this help message")
		("V,version", "Print just the version number")

		("r,refresh", "Refresh MAINTAINERS file and update (fetch origin) $VULNS_GIT and "
			      "$LINUX_GIT if present",
			cxxopts::value(gm.refresh)->default_value("false"))
		("i,init", "Clone upstream repositories; you need to provide at least "
			   "-k or -v or both!",
			cxxopts::value(gm.init)->default_value("false"))

		("D,no_db", "Do not fetch/process conf_file_map.sqlite db and therefore do not "
			    "report backporters",
			cxxopts::value(gm.no_db)->default_value("false"))
	;
	options.add_options("paths")
		("m,maintainers", "Custom path to the MAINTAINERS file instead of "
				  "$HOME/.cache/suse-get-maintainers/MAINTAINERS",
			cxxopts::value(gm.maintainers))
		("k,kernel_tree", "Clone of the mainline kernel repo ($LINUX_GIT)",
			cxxopts::value(gm.kernel_tree))
		("o,origin", "Use some other remote than origin (useful only for $LINUX_GIT)",
			cxxopts::value(gm.origin)->default_value("origin"))
		("v,vulns", "Path to the clone of https://git.kernel.org/pub/scm/linux/security/vulns.git ($VULNS_GIT)",
			cxxopts::value(gm.vulns))
		("b,cve_branch", "Which branch do we care about in $VULNS_GIT repository",
			cxxopts::value(gm.cve_branch)->default_value("origin/master"))
	;
	options.add_options("query")
		("s,sha", "SHA of a commit for which we want to find owners; - as stdin batch mode "
			  "implies CSV output. "
			  "This option can be provided multiple times with different values. "
			  "SHA could be in shortened form of at least 12 characters.",
			cxxopts::value(shas))
		("p,path", "Path for which we want to find owners; - as stdin batch mode implies "
			   "CSV output. "
			   "This option can be provided multiple times with different values.",
			cxxopts::value(paths))
		("d,diff", "Path to a patch we want to find owners; - as stdin batch mode implies "
			   "CSV output. "
			   "This option can be provided multiple times with different values.",
			cxxopts::value(diffs))
		("c,cve", "CVE number for which we want to find owners; - as stdin batch mode "
			  "implies CSV output. "
			  "This option can be provided multiple times with different values.",
			cxxopts::value(cves))
		("w,whois", "Look-up a maintainer and show his subsystems",
			cxxopts::value(gm.whois))
		("g,grep", "Grep maintainers (both emails and names) and subsystems and show the "
			   "list of maintainer,subsystem for the matches; doesn't support -j yet",
			cxxopts::value(gm.grep))
		("f,fixes", "Grep maintainers (both emails and names) and subsystems and show the "
			    "list of current fixes for the matches (EXPERIMENTAL)",
			cxxopts::value(gm.fixes))
		("C,all_cves", "Resolve all kernel CVEs and find owners for them; CSV output; "
			       "use -j or --json option for JSON",
			cxxopts::value(gm.all_cves)->default_value("false"))
		("R,rejected", "Query rejected CVEs instead of the published ones. "
			       "To be used with -c, -C and -y.",
			cxxopts::value(gm.rejected)->default_value("false"))
		("y,year", "Resolve all kernel CVEs from a given year; CSV output; "
			   "use -j or --json option for JSON",
			cxxopts::value(gm.year)->default_value("0"))
		("skip-suse", "Skip SUSE's MAINTAINERS file",
			cxxopts::value(gm.skipSUSE)->default_value("0"))
		("skip-upstream", "Skip upstream's MAINTAINERS file",
			cxxopts::value(gm.skipUpstream)->default_value("0"))
	;
	options.add_options("output")
		("j,json", "Output JSON",
			cxxopts::value(gm.json)->default_value("false"))
		("S,csv", "Output CSV",
			cxxopts::value(gm.csv)->default_value("false"))
		("a,colors_always", "Always show colors; by default, they only show when the stdout "
				    "is connected to the teminal",
			cxxopts::value(gm.colors)->default_value("false"))
		("grep_names_only", "Print only names/e-mails in the --grep output; "
				    "can still be tuned by --names",
			cxxopts::value(gm.grep_names_only)->default_value("false"))
		("n,names", "Include full names with the emails; by default, just emails are extracted",
			cxxopts::value(gm.names)->default_value("false"))
		("t,trace", "Be a bit more verbose about how we got there on STDERR",
			cxxopts::value(gm.trace)->default_value("false"))
		("N,no_translation", "Do not translate to bugzilla emails",
			cxxopts::value(gm.no_translation)->default_value("false"))
		("M,only_maintainers", "Do not analyze the patches/commits; only MAINTAINERS files",
			cxxopts::value(gm.only_maintainers)->default_value("false"))
	;

	try {
		const auto opts = options.parse(argc, argv);
		if (opts.contains("help")) {
			std::cout << options.help();
			throw 0;
		}
		if (opts.contains("version")) {
			std::cout << SUSE_GET_MAINTAINERS_VERSION << '\n';
			throw 0;
		}
		// TODO
		if (gm.no_translation)
			do_not_translate = true;
		// END TODO
		if (opts.contains("year")) {
			if (gm.year < 1999 || gm.year > 9999)
				fail_with_message(optarg, " is a year that doesn't make sense for CVE!");
			gm.all_cves = true;
		}

		moveVecToSet(shas, gm.shas);
		moveVecToSet(paths, gm.paths);
		moveVecToSet(diffs, gm.diffs);
		moveVecToSet(cves, gm.cves);
		if (gm.shas.contains("-") || gm.paths.contains("-") || gm.diffs.contains("-") ||
				gm.cves.contains("-"))
			gm.from_stdin = true;

		if (!gm.colors && isatty(1))
			gm.colors = true;

		if (gm.cves.empty() && gm.diffs.empty() && gm.shas.empty() && gm.paths.empty() &&
				!gm.all_cves && !gm.refresh && !gm.init && gm.whois.empty() &&
				gm.grep.empty() && gm.fixes.empty())
			fail_with_message("You must provide either --sha (-s), --path (-p), "
					  "--diff (-d), --cve (-c), --year (y), --all_cves (-C), "
					  "--init (-i), --grep (-g), --whois (-w) or --fixes (-f)!  "
					  "See --help (-h) for details!");

		if (gm.init && gm.kernel_tree.empty() && gm.vulns.empty())
			fail_with_message("You must provide at least --kernel_tree (-k) or --vulns (-v) or both!");
	} catch (const cxxopts::exceptions::parsing &e) {
		std::cerr << "arguments error: " << e.what() << '\n';
		std::cerr << options.help();
		throw 1;
	}
}

std::unique_ptr<OutputFormatter> getFormatter(bool simple)
{
	if (simple)
		return std::make_unique<OutputFormatterSimple>(translateEmail, gm.names);
	if (gm.json)
		return std::make_unique<OutputFormatterJSON>(translateEmail, gm.names);
	return std::make_unique<OutputFormatterCSV>(translateEmail, gm.names);
}

bool whois(const SlKernCVS::Maintainers::MaintainersType &stanzas)
{
	bool found = false;
	for (const auto& s: stanzas) {
		for (const auto &p: s.maintainers())
			if (p.email() == gm.whois || p.email().starts_with(gm.whois + "@")) {
				std::cout << s.name() << "\n";
				found = true;
			}
	}
	return found;
}

bool grep(const SlKernCVS::Maintainers::MaintainersType &stanzas)
{
	const auto re = std::regex(gm.grep, std::regex::icase | std::regex::optimize);
	bool found = false;
	std::unordered_set<std::string> uniqueEmails;
	auto formatter = getFormatter(false);
	for (const auto& s: stanzas) {
		for (const auto &p: s.maintainers())
			try {
				if (std::regex_search(p.email(), re) ||
						std::regex_search(p.name(), re) ||
						std::regex_search(s.name(), re)) {
					if (gm.grep_names_only &&
							!uniqueEmails.emplace(p.email()).second)
						continue;
					formatter->newObj();
					formatter->add("email", p.pretty(gm.names), gm.names);
					if (!gm.grep_names_only)
						formatter->add("subsystem", s.name(), true);
					found = true;
				}
			} catch (const std::regex_error& e) {
				fail_with_message(gm.grep + ": " + e.what());
			}
	}
	if (found)
		formatter->print();
	return found;
}

// unfortunately, the current format is required by tracking fixes v2
std::string maintainer_file_name_from_subsystem(const std::string &s)
{
	std::string ret;
	for (char c: s) {
		if (isspace(c) || c == '/')
			ret.push_back('_');
		else if (isalnum(c))
			ret.push_back(tolower(c));
	}
	if (ret.empty())
		fail_with_message("The subsystem name \"" + s + "\" is so bizarre that it ended up being empty!");
	return ret;
}

bool fixes(const SlKernCVS::Maintainers::MaintainersType &stanzas,
	   const SlCVEs::CVEHashMap &cve_hash_map,
	   const SlCVEs::CVE2Bugzilla &cve_to_bugzilla)
{
	const auto re = std::regex(gm.fixes, std::regex::icase | std::regex::optimize);
	bool found = false;
	std::set<std::string> files;
	for (const auto& s: stanzas) {
		for (const auto &p: s.maintainers())
			try {
				if (std::regex_search(p.email(), re) ||
						std::regex_search(p.name(), re) ||
						std::regex_search(s.name(), re)) {
					files.insert(maintainer_file_name_from_subsystem(s.name()));
					found = true;
				}
			} catch (const std::regex_error& e) {
				fail_with_message(gm.fixes + ": " + e.what());
			}
	}
	for (const auto &mf: files) {
		const auto mf_on_the_disk = SlCurl::LibCurl::fetchFileIfNeeded(gm.cacheDir / mf,
									       "http://fixes.prg2.suse.org/current/" + mf,
									       false, true,
									       std::chrono::hours{12});
		if (gm.csv)
			std::cout << "commit,subsys-part,sle-versions,bsc,cve\n";
		else
			std::cout << "--------------------------------------------------------------------------------\n";
		if (mf_on_the_disk.empty()) {
			std::cout << "No fixes for " << mf << ".\n";
			continue;
		}

		if (gm.trace)
			std::cerr << mf_on_the_disk << '\n';

		std::ifstream file{mf_on_the_disk};
		if (!file.is_open())
			fail_with_message("Unable to open file: ", mf_on_the_disk);

		enum {
			commit, subsys, sle_version, bsc, cve, last
		};

		std::string csv_details[last];
		for (std::string line; getline(file, line);) {
			std::string possible_cve;

			const auto possible_sha = (line.size() > 13 && line[12] == ' ') ?
						line.substr(0, 12) : "nope";
			if (SlHelpers::String::isHex(possible_sha)) {
				possible_cve = cve_hash_map.get_cve(possible_sha);
				csv_details[commit] = possible_sha;
			} else if (gm.csv) {
				std::istringstream line_iss(line);
				std::string considered, for_, version_;
				line_iss >> considered >> for_ >> version_;
				if(considered == "Considered" && for_ == "for") {
					if (csv_details[sle_version] != "")
						csv_details[sle_version] += ";";
					csv_details[sle_version] += version_;
				} else if (line.length() == 0 && csv_details[commit] != "") {
					std::cout << csv_details[commit] << "," <<
						     csv_details[subsys] << "," <<
						     csv_details[sle_version] << "," <<
						     csv_details[bsc] << "," <<
						     csv_details[cve] <<
						     '\n';
					std::fill_n(csv_details, last, "");
				}
				continue;
			}

			if (gm.csv) {
				const auto last_col = line.rfind(": ");
				if (last_col != std::string::npos) {
					csv_details[subsys] = line.substr(13, last_col - 13);
					const std::string replace_chars = ",;()[]{}";
					for (size_t loc; (loc = csv_details[subsys].find_first_of(replace_chars)) != std::string::npos;)
						csv_details[subsys] = csv_details[subsys].replace(loc, 1, "");
					for (size_t loc; (loc = csv_details[subsys].find(": ")) != std::string::npos;)
						csv_details[subsys] = csv_details[subsys].replace(loc, 2, ";");
				}

				if (!possible_cve.empty()) {
					csv_details[cve] = possible_cve;

					const std::string possible_bsc = cve_to_bugzilla.get_bsc(possible_cve);
					if (!possible_bsc.empty())
						csv_details[bsc] = possible_bsc.substr(4);
				}
			} else {
				std::cout << line << '\n';
				if (!possible_cve.empty()) {
					std::cout << "        " << possible_cve;
					const std::string possible_bsc = cve_to_bugzilla.get_bsc(possible_cve);
					if (!possible_bsc.empty())
						std::cout << " https://bugzilla.suse.com/show_bug.cgi?id=" <<
							     possible_bsc.substr(4) << '\n';
				}
			}
		}
		if (gm.csv)
			std::cout << "\n";
	}
	return found;
}

template<typename T = std::string>
std::set<T> read_stdin_sans_new_lines()
{
	std::set<T> ret;

	for (std::string line; std::getline(std::cin, line);)
		ret.insert(SlHelpers::String::trim(line));

	return ret;
}

void for_all_stanzas(const SQLConn &db,
		     const SlKernCVS::Maintainers &maintainers,
		     const PathsOrPeople::Paths &paths,
		     OutputFormatter &formatter)
{
	if (!gm.skipSUSE)
		if (const auto stanza = maintainers.findBestMatch(paths)) {
			if (gm.trace)
				std::cerr << "STANZA: " << stanza->name() << std::endl;
			formatter.addStanza(*stanza);
			return;
		}

	if (!gm.skipUpstream)
		if (const auto stanza = maintainers.findBestMatchUpstream(paths)) {
			if (gm.trace)
				std::cerr << "Upstream STANZA: " << stanza->name() << std::endl;
			formatter.addStanza(*stanza);
			return;
		}

	if (db) {
		std::unordered_map<std::string, unsigned> emails_and_counts_m;
		for (const auto &path: paths) {
			auto mOpt = db.get_maintainers(path.filename(), path.parent_path(), 4);
			if (!mOpt)
				fail_with_message("Failed to query.");
			for (auto &m : *mOpt) {
				const auto email = std::move(std::get<std::string>(m[0]));
				const auto count = std::get<int>(m[1]);
				emails_and_counts_m[email] += count;
			}
		}
		if (!emails_and_counts_m.empty()) {
			std::vector<std::pair<std::string, unsigned>> emails_and_counts_v;
			for (const auto &e: emails_and_counts_m)
				emails_and_counts_v.push_back({ std::move(e.first), e.second });
			std::sort(emails_and_counts_v.begin(), emails_and_counts_v.end(),
				  [](const auto &a, const auto &b) {
				return a.second > b.second;
			});
			SlKernCVS::Stanza s("Backporter");
			for (const auto &e: emails_and_counts_v)
				s.add_backporter("Backporter", e.first, e.second, translateEmail);
			if (gm.trace)
				std::cerr << "Backporters:" << std::endl;
			formatter.addStanza(s);
			return;
		}
	}

	thread_local SlKernCVS::Stanza catch_all_maintainer{"Base", "Kernel Developers at SUSE",
							    "kernel@suse.de"};
	if (gm.trace)
		std::cerr << "STANZA: " << catch_all_maintainer.name() << std::endl;
	formatter.addStanza(catch_all_maintainer);
}

void handleInit()
{
	if (!gm.kernel_tree.empty()) {
		if (!SlGit::Repo::clone(gm.kernel_tree, "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"))
			fail_with_message(git_error_last()->message);
		std::cout << "\n\nexport LINUX_GIT=" << gm.kernel_tree <<
			     " # store into ~/.bashrc\n\n\n";
	}
	if (!gm.vulns.empty()) {
		if (!SlGit::Repo::clone(gm.vulns, "https://git.kernel.org/pub/scm/linux/security/vulns.git"))
			fail_with_message(git_error_last()->message);
		std::cout << "\n\nexport VULNS_GIT=" << gm.vulns << " # store into ~/.bashrc\n\n\n";
	}
}

void handleFixes(const SlKernCVS::Maintainers::MaintainersType &maintainers)
{
	const auto cve_hash_map = SlCVEs::CVEHashMap::create(gm.vulns,
							     SlCVEs::CVEHashMap::ShaSize::Short,
							     gm.cve_branch, gm.year, gm.rejected);
	if (!cve_hash_map)
		fail_with_message("Unable to load kernel vulns database git tree: ", gm.vulns);
	constexpr const char cve2bugzilla_url[] = "https://gitlab.suse.de/security/cve-database/-/raw/master/data/cve2bugzilla";
	const auto cve2bugzilla_file = SlCurl::LibCurl::fetchFileIfNeeded(gm.cacheDir / "cve2bugzilla.txt",
									  cve2bugzilla_url,
									  false, false,
									  std::chrono::hours{12});
	const auto cve_to_bugzilla = SlCVEs::CVE2Bugzilla::create(cve2bugzilla_file);
	if (!cve_to_bugzilla)
		fail_with_message("Couldn't load cve2bugzilla.txt");
	if (!fixes(maintainers, *cve_hash_map, *cve_to_bugzilla))
		fail_with_message("unable to find a match for " + gm.fixes +
				  " in maintainers or subsystems");
}

void handleWhois(const SlKernCVS::Maintainers &maintainers)
{
	if (!whois(maintainers.maintainers()) &&
			!whois(maintainers.upstream_maintainers()))
		fail_with_message("unable to find " + gm.whois + " among maintainers");
}

void handleGrep(const SlKernCVS::Maintainers &maintainers)
{
	if (!grep(maintainers.maintainers()) &&
			!grep(maintainers.upstream_maintainers()))
		fail_with_message("unable to find a match for " + gm.grep +
				  " in maintainers or subsystems");
}

void handleRefresh()
{
	if (!gm.vulns.empty() && !SlGit::Repo::update(gm.vulns, "origin"))
		throw 1;
	if (!gm.kernel_tree.empty() && !SlGit::Repo::update(gm.kernel_tree, gm.origin))
		throw 1;
}

void handlePaths(const SlKernCVS::Maintainers &maintainers, const SQLConn &db)
{
	if (gm.from_stdin)
		gm.paths = read_stdin_sans_new_lines<std::filesystem::path>();

	bool complex = gm.paths.size() > 1 || gm.json || gm.csv || gm.from_stdin;
	const auto formatter = getFormatter(!complex);
	for (const auto &p: gm.paths) {
		formatter->newObj();
		if (complex)
			formatter->add("path", p.string(), true);
		for_all_stanzas(db, maintainers, {p}, *formatter);
	}
	formatter->print();
}

PathsOrPeople
get_paths_from_patch(const std::filesystem::path &path, bool skip_signoffs)
{
	const auto path_to_patch = std::filesystem::absolute(path);

	std::ifstream file(path_to_patch);
	if (!file.is_open())
		fail_with_message("Unable to open diff file: ", path_to_patch);

	PathsOrPeople::Paths paths;
	SlKernCVS::Stanza::Maintainers people;
	bool signoffs = true;
	for (std::string line; std::getline(file, line); ) {
		line.erase(0, line.find_first_not_of(" \t"));
		if (!skip_signoffs && signoffs) {
			if (line.starts_with("From") || line.starts_with("Author")) {
				if (const auto p = SlKernCVS::Person::parsePerson(line, SlKernCVS::Role::Author))
					if (SlHelpers::SUSE::isSUSEAddress(p->email())) {
						people.push_back(std::move(*p));
						continue;
					}
			}
			if (const auto p = SlKernCVS::Person::parse(line))
				if (SlHelpers::SUSE::isSUSEAddress(p->email())) {
					people.push_back(std::move(*p));
					continue;
				}
			if (line.starts_with("---")) {
				signoffs = false;
				continue;
			}
		}

		if (line.starts_with("--- a/") || line.starts_with("+++ b/"))
			paths.insert(line.substr(6));
	}
	if (people.empty())
		return paths;
	else
		return people;
}

void handleDiffs(const SlKernCVS::Maintainers &maintainers, const SQLConn &db)
{
	if (gm.from_stdin)
		gm.diffs = read_stdin_sans_new_lines<std::filesystem::path>();

	bool complex = gm.diffs.size() > 1 || gm.json || gm.csv || gm.from_stdin;
	const auto formatter = getFormatter(!complex);
	for (const auto &ps: gm.diffs) {
		formatter->newObj();
		try {
			const auto pop = get_paths_from_patch(ps, gm.only_maintainers);
			if (gm.trace && pop.holdsPaths()) {
				std::cerr << "patch " << ps << " contains the following paths: " << std::endl;
				for (const auto &p: pop.paths())
					std::cerr << '\t' << p << std::endl;
			}
			if (complex)
				formatter->add("diff", ps.string(), true);
			if (const auto people = pop.peopleOpt())
				formatter->addPeople(*people);
			else
				for_all_stanzas(db, maintainers, pop.paths(), *formatter);
		} catch (...) {
			if (!complex)
				throw;
		}
	}
	formatter->print();
}

void handleCVEs(std::optional<SlCVEs::CVEHashMap> &cve_hash_map)
{
	if (gm.vulns.empty())
		fail_with_message("Provide a path to kernel vulns database git tree either via -v or $VULNS_GIT");

	cve_hash_map = SlCVEs::CVEHashMap::create(gm.vulns, SlCVEs::CVEHashMap::ShaSize::Long,
						  gm.cve_branch, gm.year, gm.rejected);
	if (!cve_hash_map)
		fail_with_message("Unable to load kernel vulns database git tree: ", gm.vulns);

	if (gm.all_cves) {
		gm.cves = cve_hash_map->get_all_cves();
		gm.from_stdin = false;
	}

	if (gm.from_stdin)
		gm.cves = read_stdin_sans_new_lines();

	for (const auto &c: gm.cves) {
		const std::vector<std::string> shas = cve_hash_map->get_shas(c);
		if (shas.empty()) {
			Clr(std::cerr, Clr::YELLOW) << "Unable to translate CVE number (" << c
						    << ") to SHA hash";
			continue;
		}
		for (const std::string &s: shas) {
			gm.shas.insert(s);
			if (gm.trace)
				std::cerr << "CVE(" << c << ") is SHA(" << s << ")" << std::endl;
		}
	}
}

void handleSHAs(const SlKernCVS::Maintainers &maintainers,
		const std::optional<SlCVEs::CVEHashMap> &cve_hash_map,
		const SQLConn &db)
{
	if (gm.kernel_tree.empty())
		fail_with_message("Provide a path to mainline git kernel tree either via -k or $LINUX_GIT");

	auto rkOpt = SlGit::Repo::open(gm.kernel_tree);
	if (!rkOpt)
		fail_with_message("Unable load kernel tree: ", gm.kernel_tree, " (",
				  git_error_last()->message, ")");

	if (gm.shas.size() == 1 && gm.from_stdin && !cve_hash_map)
		gm.shas = read_stdin_sans_new_lines();

	const auto formatter = getFormatter(gm.shas.size() == 1 && !gm.csv && !gm.json);
	GitHelpers::searchCommit(*rkOpt, gm.shas, gm.only_maintainers, gm.trace,
				 [&maintainers, &cve_hash_map, &db, &formatter]
				 (std::string sha, PathsOrPeople pop) {
		if (gm.trace && pop.holdsPaths()) {
			std::cerr << "SHA " << sha << " contains the following paths: " << std::endl;
			for (const auto &p: pop.paths())
				std::cerr << '\t' << p << '\n';
		}
		formatter->newObj();
		if (cve_hash_map)
			formatter->add("cve", cve_hash_map->get_cve(sha));
		formatter->add("sha", sha);
		if (const auto people = pop.peopleOpt()) {
			formatter->addPeople(*people);
		} else
			for_all_stanzas(db, maintainers, pop.paths(), *formatter);
	});
	formatter->print();
}

int handled_main(int argc, char **argv)
{
	std::cin.tie(nullptr);
	std::ios::sync_with_stdio(false);

	parse_options(argc, argv);
	Clr::forceColor(true);
	Clr::forceColorValue(gm.colors);

	gm.cacheDir = SlHelpers::HomeDir::createCacheDir("suse-get-maintainers");
	if (gm.cacheDir.empty())
		fail_with_message("Unable to create a cache dir");

	if (gm.maintainers.empty() || !std::filesystem::exists(gm.maintainers))
		gm.maintainers = SlCurl::LibCurl::fetchFileIfNeeded(gm.cacheDir / "MAINTAINERS",
						      "https://kerncvs.suse.de/MAINTAINERS",
						      gm.refresh, false, std::chrono::hours{12});

	if (!gm.no_db)
		gm.conf_file_map = SlCurl::LibCurl::fetchFileIfNeeded(gm.cacheDir / "conf_file_map.sqlite",
								      "https://kerncvs.suse.de/conf_file_map.sqlite",
								      gm.refresh, false,
								      std::chrono::days{7});

	// TODO
	const auto temporary = SlCurl::LibCurl::fetchFileIfNeeded(gm.cacheDir / "user-bugzilla-map.txt",
								  "https://kerncvs.suse.de/user-bugzilla-map.txt",
								  gm.refresh, false,
								  std::chrono::hours{12});
	if (!load_temporary(translation_table, temporary))
		throw 1;
	// END TODO

	const std::size_t libgit2_limit_opened_files = (get_soft_limit_for_opened_files(min_total_opened_files) - tracking_fixes_opened_files) / libgit2_opened_files_factor;
	if (git_libgit2_opts(GIT_OPT_SET_MWINDOW_FILE_LIMIT, libgit2_limit_opened_files))
		Clr(std::cerr, Clr::YELLOW) << "Could not set a limit for opened files: " <<
					       libgit2_limit_opened_files;

	if (gm.init) {
		handleInit();
		return 0;
	}

	if (gm.vulns.empty())
		if (const auto path = SlHelpers::Env::get<std::filesystem::path>("VULNS_GIT"))
			gm.vulns = *path;
	if (gm.kernel_tree.empty())
		if (const auto path = SlHelpers::Env::get<std::filesystem::path>("LINUX_GIT"))
			gm.kernel_tree = *path;

	const auto m = SlKernCVS::Maintainers::load(gm.maintainers, gm.kernel_tree, gm.origin,
						    translateEmail);
	if (!m)
		throw 1;

	if (!gm.fixes.empty()) {
		handleFixes(m->maintainers());
		return 0;
	}

	if (!gm.whois.empty()) {
		handleWhois(*m);
		return 0;
	}

	if (!gm.grep.empty()) {
		handleGrep(*m);
		return 0;
	}

	if (gm.refresh)
		handleRefresh();

	SQLConn db;
	if (!gm.no_db)
		if (!db.open(gm.conf_file_map))
			fail_with_message("Failed to open db: ", gm.conf_file_map, ": ",
					  db.lastError());

	if (!gm.paths.empty()) {
		handlePaths(*m, db);
		return 0;
	}

	if (!gm.diffs.empty()) {
		handleDiffs(*m, db);
		return 0;
	}

	std::optional<SlCVEs::CVEHashMap> cve_hash_map;

	if (!gm.cves.empty() || gm.all_cves)
		handleCVEs(cve_hash_map);

	if (!gm.shas.empty()) {
		handleSHAs(*m, cve_hash_map, db);
		return 0;
	}

	return 0;
}

} // namespace

int main(int argc, char **argv)
{
	try {
		return handled_main(argc, argv);
	} catch (int ret) {
		return ret;
	} catch (...) {
		return 42;
	}
}
