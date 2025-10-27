#include <cxxopts.hpp>
#include <fstream>
#include <string>
#include <set>
#include <optional>
#include <cstdio>
#include <iomanip>
#include <getopt.h>
#include <unistd.h>
#include <filesystem>

#include <sl/curl/Curl.h>
#include <sl/cves/CVE2Bugzilla.h>
#include <sl/cves/CVEHashMap.h>
#include <sl/git/Git.h>
#include <sl/helpers/Color.h>
#include <sl/helpers/Misc.h>
#include <sl/helpers/SUSE.h>
#include <sl/sqlite/SQLConn.h>

#include "helpers.h"
#include "GitHelpers.h"
#include "Maintainers.h"
#include "Person.h"

using namespace SGM;
using Clr = SlHelpers::Color;

namespace {

class SQLConn : public SlSqlite::SQLConn {
public:
	virtual int prepDB() {
		if (prepareStatement("SELECT user.email, sum(map.count) AS cnt "
				     "FROM user_file_map AS map "
				     "LEFT JOIN user ON map.user = user.id "
				     "WHERE map.file = (SELECT id FROM file WHERE file = :file "
				     "AND dir = (SELECT id FROM dir WHERE dir = :dir)) "
				     "GROUP BY substr(user.email, 0, instr(user.email, '@')) "
				     "ORDER BY cnt DESC, user.email "
				     "LIMIT :limit;", selGetMaintainers))
			return -1;

		return 0;
	}

	std::optional<SlSqlite::SQLConn::SelectResult>
	get_maintainers(const std::string &file, const std::string &dir, int limit) const
	{
		SlSqlite::SQLConn::SelectResult res;

		if (select(selGetMaintainers, {
				{ ":file", file },
				{ ":dir", dir },
				{ ":limit", limit },
				}, { typeid(std::string), typeid(int) }, res))
			return {};

		return res;
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
	;
	options.add_options("output")
		("j,json", "Output JSON",
			cxxopts::value(gm.json)->default_value("false"))
		("S,csv", "Output CSV",
			cxxopts::value(gm.csv)->default_value("false"))
		("a,colors_always", "Always show colors; by default, they only show when the stdout "
				    "is connected to the teminal",
			cxxopts::value(gm.colors)->default_value("false"))
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

void show_emails(const Stanza &m, const std::string &)
{
	m.for_all_maintainers([](const Person &p) {
		std::cout << p.pretty(gm.names) << '\n';
	});
}

void csv_output(const Stanza &m, const std::string &what)
{
	std::cout << what << ',' << '"' << m.name() << '"';
	m.for_all_maintainers([](const Person &p) {
		std::cout << ',' << p.pretty(gm.names);
	});
	std::cout << '\n';
}

void json_output(const Stanza &m, const std::string &what)
{
	std::cout << what << ',' << "\n    ";
	Clr(Clr::BLUE) << Clr::NoNL << "\"subsystem\"";
	std::cout << ": ";
	Clr(Clr::GREEN) << Clr::NoNL << std::quoted(m.name());
	std::cout << ",\n    ";
	Clr(Clr::BLUE) << Clr::NoNL << "\"emails\"";
	std::cout << ": [\n      ";
	bool first = true;
	int backport_counts = 0;
	m.for_all_maintainers([&first, &backport_counts](const Person &p) {
		backport_counts += p.count();
		if (!first)
			std::cout << ",\n      ";
		first = false;
		Clr(Clr::GREEN) << Clr::NoNL << std::quoted(p.pretty(gm.names));
	});
	if (backport_counts > 0) {
		std::cout << "\n    ],\n    ";
		Clr(Clr::BLUE) << Clr::NoNL << "\"counts\"";
		std::cout << ": [\n      ";
		first = true;
		m.for_all_maintainers([&first](const Person &p) {
			if (!first)
				std::cout << ",\n      ";
			first = false;
			Clr(Clr::GREEN) << Clr::NoNL << p.count();
		});
	}
	std::cout << "\n    ]\n  }";
}

void show_people(const std::vector<Person> &sb, const std::string &what, bool simple)
{

	if (simple) {
		std::set<std::string> duplicate_set;
		for (const Person &p: sb) {
			std::string tmp_email = translateEmail(p.email()); // TODO
			if (duplicate_set.contains(tmp_email))
				continue;
			duplicate_set.insert(tmp_email);
			std::cout << p.pretty([&tmp_email](const std::string &) -> std::string {
				return tmp_email;
			}, gm.names) << '\n';
		}
	} else if (gm.json) {
		std::cout << what << ',' << "\n    ";
		Clr(Clr::BLUE) << Clr::NoNL << "\"roles\"";
		std::cout << ": [\n      ";
		bool first = true;
		int backport_counts = 0;
		for (const Person &p: sb) {
			backport_counts += p.count();
			if (!first)
				std::cout << ",\n      ";
			first = false;
			Clr(Clr::GREEN) << Clr::NoNL << std::quoted(p.role().toString());
		}
		std::cout << "\n    ],\n    ";
		Clr(Clr::BLUE) << Clr::NoNL << "\"emails\"";
		std::cout << ": [\n      ";
		first = true;
		for (const Person &p: sb) {
			if (!first)
				std::cout << ",\n      ";
			first = false;
			Clr(Clr::GREEN) << Clr::NoNL << std::quoted(p.pretty(translateEmail,
									     gm.names));
		}
		if (backport_counts > 0) {
			std::cout << "\n    ],\n    ";
			Clr(Clr::BLUE) << Clr::NoNL << "\"counts\"";
			std::cout << ": [\n      ";
			first = true;
			for (const Person &p: sb) {
				if (!first)
					std::cout << ",\n      ";
				first = false;
				Clr(Clr::GREEN) << Clr::NoNL << p.count();
			}
		}
		std::cout << "\n    ]\n  }";
	} else {
		std::cout << what << ',' << '"';
		bool first = true;
		for (const Person &p: sb) {
			if (!first)
				std::cout << '/';
			first = false;
			std::cout << p.role().toString();
		}
		std::cout << '"' << ',';
		first = true;
		for (const Person &p: sb) {
			if (!first)
				std::cout << ',';
			first = false;

			std::cout << p.pretty(translateEmail, gm.names);
		}
		std::cout << '\n';
	}
}

bool whois(const Maintainers::MaintainersType &stanzas, const std::string &whois)
{
	bool found = false;
	for (const auto& s: stanzas) {
		s.for_all_maintainers([&s, &whois, &found](const Person &p) {
			if (p.email() == whois || p.email().starts_with(whois + "@")) {
				std::cout << s.name() << "\n";
				found = true;
			}
		});
	}
	return found;
}

bool grep(const Maintainers::MaintainersType &stanzas, const std::string &grep, bool names)
{
	const auto re = std::regex(grep, std::regex::icase | std::regex::optimize);
	bool found = false;
	for (const auto& s: stanzas) {
		s.for_all_maintainers([&re, &s, &grep, &found, names](const Person &p) {
			try {
				if (std::regex_search(p.email(), re) ||
						std::regex_search(p.name(), re) ||
						std::regex_search(s.name(), re)) {
					if (names)
						std::cout << '"' << p.pretty(true) << '"';
					else
						std::cout << p.email();
					std::cout << ",\"" << s.name() << "\"\n";
					found = true;
				}
			} catch (const std::regex_error& e) {
				fail_with_message(grep + ": " + e.what());
			}
		});
	}
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

bool fixes(const std::vector<Stanza> &stanzas, const std::string &grep, bool csv, bool trace,
	   const SlCVEs::CVEHashMap &cve_hash_map, const SlCVEs::CVE2Bugzilla &cve_to_bugzilla)
{
	const auto re = std::regex(grep, std::regex::icase | std::regex::optimize);
	bool found = false;
	std::set<std::string> files;
	for (const auto& s: stanzas) {
		s.for_all_maintainers([&re, &s, &grep, &found, &files](const Person &p) {
			try {
				if (std::regex_search(p.email(), re) ||
						std::regex_search(p.name(), re) ||
						std::regex_search(s.name(), re)) {
					files.insert(maintainer_file_name_from_subsystem(s.name()));
					found = true;
				}
			} catch (const std::regex_error& e) {
				fail_with_message(grep + ": " + e.what());
			}
		});
	}
	for (const auto &mf: files) {
		const auto mf_on_the_disk = SlCurl::LibCurl::fetchFileIfNeeded(gm.cacheDir / mf, "http://fixes.prg2.suse.org/current/" + mf, false, true, std::chrono::hours{12});
		if (csv)
			std::cout << "commit,subsys-part,sle-versions,bsc,cve\n";
		else
			std::cout << "--------------------------------------------------------------------------------\n";
		if (!mf_on_the_disk.empty()) {
			if (trace)
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

				auto line_not_hex_to_csv = [&csv_details, &line]() {
					std::istringstream line_iss(line);
					std::string considered, for_, version_;
					line_iss >> considered >> for_ >> version_;
					if(considered == "Considered" && for_ == "for") {
						if (csv_details[sle_version] != "")
							csv_details[sle_version] += ";";
						csv_details[sle_version] += version_;
					} else if (line.length() == 0 && csv_details[commit] != "") {
						std::cout << csv_details[commit] << ","
									<< csv_details[subsys] << ","
									<< csv_details[sle_version] << ","
									<< csv_details[bsc] << ","
									<< csv_details[cve]
									<< '\n';
						std::fill_n(csv_details, last, "");
					}
				};

				auto line_is_hex_to_csv = [&csv_details, &possible_cve, &line, &cve_to_bugzilla]() {
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
				};

				const auto possible_sha = (line.size() > 13 && line[12] == ' ') ? line.substr(0, 12) : "nope";
				if (SlHelpers::String::isHex(possible_sha)) {
					possible_cve = cve_hash_map.get_cve(possible_sha);
					csv_details[commit] = possible_sha;
				} else if (csv) {
					line_not_hex_to_csv();
					continue;
				}
				if (csv) {
					line_is_hex_to_csv();
				} else {
					std::cout << line << '\n';
					if (!possible_cve.empty()) {
						std::cout << "        " << possible_cve;
						const std::string possible_bsc = cve_to_bugzilla.get_bsc(possible_cve);
						if (!possible_bsc.empty())
							std::cout << " https://bugzilla.suse.com/show_bug.cgi?id=" << possible_bsc.substr(4) << '\n';
					}
				}
			}
			if (csv)
				std::cout << "\n";
		} else
			std::cout << "No fixes for " << mf << ".\n";
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

std::optional<const Stanza *> find_best_match(const std::vector<Stanza> &sl,
					      const std::set<std::filesystem::path> &paths)
{
	std::optional<const Stanza *> ret;
	unsigned best_weight = 0;
	for(const auto &s: sl) {
		unsigned weight = 0;
		for (const auto &path: paths)
			weight += s.match_path(path);
		if (weight > best_weight) {
			ret.emplace(&s);
			best_weight = weight;
		}
	}
	return ret;
}

struct GetMaintainers
{
	std::string email;
	int count;
};

template<typename F>
void for_all_stanzas(const SQLConn &db,
		     const Maintainers &maintainers,
		     const std::set<std::filesystem::path> &paths,
		     F pp,
		     const std::string &what)
{
	std::optional<const Stanza *> stanza = find_best_match(maintainers.maintainers(), paths);

	if (stanza.has_value()) {
		if (gm.trace)
			std::cerr << "STANZA: " << stanza.value()->name() << std::endl;
		pp(*stanza.value(), what);
		return;
	}

	stanza = find_best_match(maintainers.upstream_maintainers(), paths);

	if (stanza.has_value()) {
		if (gm.trace)
			std::cerr << "Upstream STANZA: " << stanza.value()->name() << std::endl;
		pp(*stanza.value(), what);
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
			struct GetMaintainers
			{
				std::string email;
				unsigned count;
			};

			std::vector<GetMaintainers> emails_and_counts_v;
			for (const auto &e: emails_and_counts_m)
				emails_and_counts_v.push_back(GetMaintainers(std::move(e.first), e.second));
			std::sort(emails_and_counts_v.begin(), emails_and_counts_v.end(), [](const GetMaintainers &a, const GetMaintainers &b) {
				return a.count > b.count;
			});
			Stanza s("Backporter");
			for (const auto &e: emails_and_counts_v)
				s.add_backporter("M: Backporter <" + e.email + ">", e.count,
						 translateEmail);
			if (gm.trace)
				std::cerr << "Backporters:" << std::endl;
			pp(s, what);
			return;
		}
	}

	thread_local auto catch_all_maintainer = Stanza{"Base", "F: Kernel Developers at SuSE <kernel@suse.de>"};
	if (gm.trace)
		std::cerr << "STANZA: " << catch_all_maintainer.name() << std::endl;
	pp(catch_all_maintainer, what);
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

void handleFixes(const Maintainers::MaintainersType &maintainers)
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
	if (!fixes(maintainers, gm.fixes, gm.csv, gm.trace, *cve_hash_map, *cve_to_bugzilla))
		fail_with_message("unable to find a match for " + gm.fixes +
				  " in maintainers or subsystems");
}

void handleWhois(const Maintainers &maintainers)
{
	if (!whois(maintainers.maintainers(), gm.whois))
		if (!whois(maintainers.upstream_maintainers(), gm.whois))
			fail_with_message("unable to find " + gm.whois + " among maintainers");
}

void handleGrep(const Maintainers &maintainers)
{
	if (!grep(maintainers.maintainers(), gm.grep, gm.names))
		if (!grep(maintainers.upstream_maintainers(), gm.grep, gm.names))
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

void handlePaths(const Maintainers &maintainers, const SQLConn &db)
{
	if (gm.from_stdin)
		gm.paths = read_stdin_sans_new_lines<std::filesystem::path>();

	if (gm.paths.size() > 1 || gm.json || gm.csv || gm.from_stdin) {
		if (gm.json)
			std::cout << "[\n";
		bool first = true;
		for (const auto &p: gm.paths) {
			std::ostringstream what;
			if (gm.json) {
				if (!first)
					what << ",\n";
				first = false;
				what << "  {\n    ";
				Clr(what, Clr::BLUE) << Clr::NoNL << "\"path\"";
				what << ": ";
				Clr(what, Clr::GREEN) << Clr::NoNL << '"' << p << '"';
			} else
				what << p;
			for_all_stanzas(db, maintainers, {p},
					gm.json ? json_output : csv_output, what.str());
		}
		if (gm.json)
			std::cout << "\n]\n";
	} else
		for_all_stanzas(db, maintainers, gm.paths, show_emails, "");
}

std::variant<std::set<std::filesystem::path>, std::vector<Person>>
get_paths_from_patch(const std::filesystem::path &path, bool skip_signoffs)
{
	std::variant<std::set<std::filesystem::path>, std::vector<Person>> ret;
	const auto path_to_patch = std::filesystem::absolute(path);

	std::ifstream file(path_to_patch);
	if (!file.is_open())
		fail_with_message("Unable to open diff file: ", path_to_patch);

	thread_local const auto regex_add = std::regex("^\\+\\+\\+ [ab]/(.+)", std::regex::optimize);
	thread_local const auto regex_rem = std::regex("^--- [ab]/(.+)", std::regex::optimize);

	std::set<std::filesystem::path> paths;
	std::vector<Person> people;
	bool signoffs = true;
	std::smatch match;
	for (std::string line; std::getline(file, line); ) {
		line.erase(0, line.find_first_not_of(" \t"));
		if (!skip_signoffs && signoffs) {
			if (line.starts_with("From") || line.starts_with("Author")) {
				if (const auto p = Person::parsePerson(line, Role::Author))
					if (SlHelpers::SUSE::isSUSEAddress(p->email()))
						people.push_back(std::move(*p));
			}
			if (const auto p = Person::parse(line))
				if (SlHelpers::SUSE::isSUSEAddress(p->email()))
					people.push_back(std::move(*p));
			if (line.starts_with("---"))
			    signoffs = false;
		}

		if (std::regex_search(line, match, regex_add))
			paths.insert(match.str(1));
		else if (std::regex_search(line, match, regex_rem))
			paths.insert(match.str(1));
	}
	if (people.empty())
		ret = std::move(paths);
	else
		ret = std::move(people);
	return ret;
}

void handleDiffs(const Maintainers &maintainers, const SQLConn &db)
{
	if (gm.from_stdin)
		gm.diffs = read_stdin_sans_new_lines<std::filesystem::path>();

	if (gm.diffs.size() > 1 || gm.json || gm.csv || gm.from_stdin) {
		if (gm.json)
			std::cout << "[\n";
		bool first = true;
		for (const auto &ps: gm.diffs) {
			try {
				auto s = get_paths_from_patch(ps, gm.only_maintainers);
				if (gm.trace && std::holds_alternative<std::set<std::filesystem::path>>(s)) {

					std::cerr << "patch " << ps << " contains the following paths: " << std::endl;
					for (const auto &p: std::get<std::set<std::filesystem::path>>(s))
						std::cerr << '\t' << p << std::endl;
				}
				std::ostringstream what;
				if (gm.json) {
					if (!first)
						what << ",\n";
					first = false;
					what << "  {\n    ";
					Clr(what, Clr::BLUE) << Clr::NoNL << "\"diff\"";
					what << ": ";
					Clr(what, Clr::GREEN) << Clr::NoNL << '"' << ps << '"';
				} else
					what << ps;
				if (std::holds_alternative<std::vector<Person>>(s)) {
					const std::vector<Person> sb = std::get<std::vector<Person>>(s);
					show_people(sb, what.str(), false);
				} else
					for_all_stanzas(db, maintainers,
							std::get<std::set<std::filesystem::path>>(s),
							gm.json ? json_output : csv_output,
							what.str());
			} catch (...) { continue; }
		}
		if (gm.json)
			std::cout << "\n]\n";
		return;
	}

	auto s = get_paths_from_patch(*gm.diffs.cbegin(), gm.only_maintainers);
	if (gm.trace && std::holds_alternative<std::set<std::filesystem::path>>(s)) {
		std::cerr << "patch " << *gm.diffs.cbegin() << " contains the following paths: " <<
			     std::endl;
		for (const auto &p: std::get<std::set<std::filesystem::path>>(s))
			std::cerr << '\t' << p << std::endl;
	}
	if (std::holds_alternative<std::vector<Person>>(s)) {
		const std::vector<Person> sb = std::get<std::vector<Person>>(s);
		show_people(sb, "", true);
	} else
		for_all_stanzas(db, maintainers,
				std::get<std::set<std::filesystem::path>>(s), show_emails, "");
}

void validate_cves(const std::set<std::string> &s)
{
	thread_local const auto regex_cve_number = std::regex("CVE-[0-9][0-9][0-9][0-9]-[0-9]+",
							      std::regex::optimize);
	for (const auto &str: s)
		if (!std::regex_match(str, regex_cve_number))
			Clr(std::cerr, Clr::YELLOW) << str <<
						       " does not seem to be a valid CVE number";
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

	if (gm.cves.size() > 1) {
		validate_cves(gm.cves);
		for (const auto &c: gm.cves) {
			const std::vector<std::string> shas = cve_hash_map->get_shas(c);
			for (const std::string &s: shas) {
				gm.shas.insert(s);
				if (gm.trace)
					std::cerr << "CVE(" << c << ") is SHA(" << s << ")" << std::endl;
			}
			if (shas.empty())
				std::cerr << "Unable to translate CVE number (" << c << ") to SHA hash" << std::endl;
		}
	} else {
		const std::vector<std::string> shas = cve_hash_map->get_shas(*gm.cves.cbegin());
		for (const std::string &s: shas) {
			gm.shas.insert(s);
			if (gm.trace)
				std::cerr << "CVE(" << *gm.cves.cbegin() << ") is SHA(" << s << ")" << std::endl;
		}
		if (shas.empty())
			fail_with_message("Unable to translate CVE number (", *gm.cves.cbegin(), ") to SHA hash");
	}
}

void handleSHAs(const Maintainers &maintainers,
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
	const bool simple = gm.shas.size() == 1 && !gm.from_stdin && !gm.csv && !gm.json;

	GitHelpers::validateShas(gm.shas, cve_hash_map ? 40 : 12);
	bool first = true;

	if (gm.json)
		std::cout << "[\n";

	GitHelpers::searchCommit(*rkOpt, gm.shas, gm.only_maintainers, gm.trace,
				 [&maintainers, &first, &cve_hash_map, &db, simple]
				 (const std::string &sha, const std::vector<Person> &sb,
				 const std::set<std::filesystem::path> &paths) {
		if (gm.trace && !paths.empty()) {
			std::cerr << "SHA " << sha << " contains the following paths: " << std::endl;
			for (const auto &p: paths)
				std::cerr << '\t' << p << '\n';
		}
		std::ostringstream what;
		if (gm.json) {
			if (!first)
				what << ",\n";
			first = false;
			what << "  {\n";
			if (cve_hash_map) {
				what << "    ";
				Clr(what, Clr::BLUE) << Clr::NoNL << "\"cve\"";
				what << ": ";
				Clr(what, Clr::GREEN) << Clr::NoNL << '"' <<
							 cve_hash_map->get_cve(sha) << '"';
				what << ",\n";
			}
			what << "    ";
			Clr(what, Clr::BLUE) << Clr::NoNL << "\"sha\"";
			what << ": ";
			Clr(what, Clr::GREEN) << Clr::NoNL << '"' << sha << '"';
		} else if (cve_hash_map)
			what << cve_hash_map->get_cve(sha) << ',' << sha;
		else
			what << sha;
		if (!sb.empty()) {
			show_people(sb, what.str(), simple);
		} else
			for_all_stanzas(db, maintainers, paths,
					simple ? show_emails : gm.json ? json_output : csv_output,
					what.str());
	});
	if (gm.json)
		std::cout << "\n]\n";
}

} // namespace

int main(int argc, char **argv)
{
	SGM_BEGIN;

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

	const auto m = Maintainers::load(gm.maintainers, gm.kernel_tree, gm.origin, translateEmail);
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
		if (db.open(gm.conf_file_map))
			fail_with_message("Failed to open db: ", gm.conf_file_map);

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

	SGM_END;
}
