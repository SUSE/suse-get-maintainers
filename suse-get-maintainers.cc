#include <fstream>
#include <string>
#include <set>
#include <optional>
#include <cstdio>
#include <getopt.h>

#include "helpers.h"
#include "git2.h"
#include "cves.h"
#include "curl.h"
#include "maintainers.h"
// TODO
#include "temporary.h"
// END TODO

namespace {
	void parse_options(int argc, char **argv);
	void fetch_repo(const std::string &, const std::string &);
	void show_emails(const Stanza &m, const std::string&);
	void csv_output(const Stanza &m, const std::string&);
	void json_output(const Stanza &m, const std::string&);
	void show_people(const std::vector<Person> &, const std::string &, bool);
	std::set<std::string> read_stdin_sans_new_lines();
	template<typename F>
	void for_all_stanzas(const std::vector<Stanza> &,
			     const std::vector<Stanza> &,
			     const std::set<std::string> &,
			     F pp,
			     const std::string &);

	struct gm {
		std::string maintainers;
		std::string kernel_tree;
		std::set<std::string> shas;
		std::set<std::string> paths;
		std::set<std::string> diffs;
		std::string vulns;
		std::set<std::string> cves;
		int year = 0;
		bool rejected = false;
		bool all_cves = false;
		bool json = false;
		bool csv = false;
		bool names = false;
		bool from_stdin = false;
		bool trace = false;
		bool refresh = false;
		bool init = false;
		bool no_translation = false;
		bool only_maintainers = false;
	} gm;
}

int main(int argc, char **argv)
{
	SGM_BEGIN;

	std::cin.tie(nullptr);
	std::ios::sync_with_stdio(false);

	std::vector<Stanza> maintainers;
	std::vector<Stanza> upstream_maintainers;
	std::set<std::string> suse_users;

	parse_options(argc, argv);

	if (gm.cves.empty() && gm.diffs.empty() && gm.shas.empty() && gm.paths.empty() && !gm.all_cves && !gm.refresh && !gm.init)
		fail_with_message("You must provide either --sha (-s), --path (-p), --diff (-d), --cve (-c), --year (y), --all_cves (-C) or --init (-i)!  See --help (-h) for details!");

	if (gm.init && (gm.kernel_tree.empty() && gm.vulns.empty()))
		fail_with_message("You must provide at least --kernel_tree (-k) or --vulns (-v) or both!");

	constexpr const char maintainers_url[] = "https://kerncvs.suse.de/MAINTAINERS";
	gm.maintainers = fetch_file_if_needed(gm.maintainers, "MAINTAINERS", maintainers_url, gm.trace, gm.refresh);

	// TODO
	temporary = fetch_file_if_needed(std::string(), "user-bugzilla-map.txt", "https://kerncvs.suse.de/user-bugzilla-map.txt", gm.trace, gm.refresh);
	load_temporary(translation_table, temporary);
	// END TODO

	LibGit2 libgit2_state;

	if (gm.init) {
		if (!gm.kernel_tree.empty()) {
			Repo repo;
			if (repo.clone(gm.kernel_tree, "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"))
				fail_with_message(git_error_last()->message);
			emit_message("\n\nexport LINUX_GIT=\"", gm.kernel_tree, "\" # store into ~/.bashrc\n\n");
		}
		if (!gm.vulns.empty()) {
			Repo repo;
			if (repo.clone(gm.vulns, "https://git.kernel.org/pub/scm/linux/security/vulns.git"))
				fail_with_message(git_error_last()->message);
			emit_message("\n\nexport VULNS_GIT=\"", gm.vulns, "\" # store into ~/.bashrc\n\n");
		}
		return 0;
	}

	try_to_fetch_env(gm.vulns, "VULNS_GIT");
	try_to_fetch_env(gm.kernel_tree, "LINUX_GIT");

	load_maintainers_file(maintainers, suse_users, gm.maintainers);
	if (!gm.kernel_tree.empty())
		load_upstream_maintainers_file(upstream_maintainers, suse_users, gm.kernel_tree);

	if (gm.refresh) {
		if (!gm.vulns.empty())
			fetch_repo(gm.vulns, "origin");
		if (!gm.kernel_tree.empty())
			fetch_repo(gm.kernel_tree, "origin");
	}

	if (!gm.paths.empty()) {
		if (gm.from_stdin)
			gm.paths = read_stdin_sans_new_lines();

		if (gm.paths.size() > 1 || gm.json || gm.csv || gm.from_stdin) {
			if (gm.json)
				std::cout << "[\n";
			bool first = true;
			for (const auto &p: gm.paths) {
				std::string what;
				if (gm.json) {
					if (!first)
						what = ",\n";
					first = false;
					what += "\t{\n\t\t\"path\": \"" + p + "\"";
				} else
					what = p;
				for_all_stanzas(maintainers, upstream_maintainers, std::set<std::string>{p}, gm.json ? json_output : csv_output, what);
			}
			if (gm.json)
				std::cout << "\n]\n";
		} else
			for_all_stanzas(maintainers, upstream_maintainers, gm.paths, show_emails, "");
		return 0;
	}

	if (!gm.diffs.empty()) {
		if (gm.from_stdin)
			gm.diffs = read_stdin_sans_new_lines();

		if (gm.diffs.size() > 1 || gm.json || gm.csv || gm.from_stdin) {
			if (gm.json)
				std::cout << "[\n";
			bool first = true;
			for (const auto &ps: gm.diffs) {
				try {
					std::variant<std::set<std::string>, std::vector<Person>> s = get_paths_from_patch(ps, suse_users, gm.only_maintainers);
					if (gm.trace && std::holds_alternative<std::set<std::string>>(s)) {

						std::cerr << "patch " << ps << " contains the following paths: " << std::endl;
						for (const auto &p: std::get<std::set<std::string>>(s))
							std::cerr << '\t' << p << std::endl;
					}
					std::string what;
					if (gm.json) {
						if (!first)
							what = ",\n";
						first = false;
						what += "\t{\n\t\t\"diff\": \"" + ps + "\"";
					} else
						what = ps;
					if (std::holds_alternative<std::vector<Person>>(s)) {
						const std::vector<Person> sb = std::get<std::vector<Person>>(s);
						show_people(sb, what, false);
					} else
						for_all_stanzas(maintainers, upstream_maintainers, std::get<std::set<std::string>>(s), gm.json ? json_output : csv_output, what);
				} catch (...) { continue; }
			}
			if (gm.json)
				std::cout << "\n]\n";
		} else {
			std::variant<std::set<std::string>, std::vector<Person>> s = get_paths_from_patch(*gm.diffs.cbegin(), suse_users, gm.only_maintainers);
			if (gm.trace && std::holds_alternative<std::set<std::string>>(s)) {
				std::cerr << "patch " << *gm.diffs.cbegin() << " contains the following paths: " << std::endl;
				for (const auto &p: std::get<std::set<std::string>>(s))
					std::cerr << '\t' << p << std::endl;
			}
			if (std::holds_alternative<std::vector<Person>>(s)) {
				const std::vector<Person> sb = std::get<std::vector<Person>>(s);
				show_people(sb, "", true);
			} else
				for_all_stanzas(maintainers, upstream_maintainers, std::get<std::set<std::string>>(s), show_emails, "");
		}
		return 0;
	}

	CVEHashMap cve_hash_map{gm.year, gm.rejected};
	bool has_cves = false;

	if (!gm.cves.empty() || gm.all_cves) {
		has_cves = true;
		if (gm.vulns.empty())
			fail_with_message("Provide a path to kernel vulns database git tree either via -v or $VULNS_GIT");

		if (!cve_hash_map.load(gm.vulns))
			fail_with_message("Unable to load kernel vulns database git tree: ", gm.vulns);

		if (gm.all_cves) {
			gm.cves = cve_hash_map.get_all_cves();
			gm.from_stdin = false;
		}

		if (gm.from_stdin)
			gm.cves = read_stdin_sans_new_lines();

		if (gm.cves.size() > 1) {
			validate_cves(gm.cves);
			for (const auto &c: gm.cves) {
				std::string sha = cve_hash_map.get_sha(c);
				if (gm.trace)
					std::cerr << "CVE(" << c << ") is SHA(" << sha << ")" << std::endl;
				if (!sha.empty())
					gm.shas.insert(sha);
				else
					std::cerr << "Unable to translate CVE number (" << c << ") to SHA hash" << std::endl;
			}
		} else {
			const std::string sha = cve_hash_map.get_sha(*gm.cves.cbegin());
			if (sha.empty())
				fail_with_message("Unable to translate CVE number (", *gm.cves.cbegin(), ") to SHA hash");
			gm.shas.insert(sha);
			if (gm.trace)
				std::cerr << "CVE(" << *gm.cves.cbegin() << ") is SHA(" << sha << ")" << std::endl;
		}
	}

	if (!gm.shas.empty()) {
		if (gm.kernel_tree.empty())
			fail_with_message("Provide a path to mainline git kernel tree either via -k or $LINUX_GIT");

		Repo rk;
		if (rk.from_path(gm.kernel_tree))
			fail_with_message("Unable load kernel tree: ", gm.kernel_tree, " (", git_error_last()->message, ")");

		if (gm.shas.size() == 1 && gm.from_stdin && !has_cves)
			gm.shas = read_stdin_sans_new_lines();
		const bool simple = gm.shas.size() == 1 && !gm.from_stdin && !gm.csv && !gm.json;

		validate_shas(gm.shas, has_cves ? 40 : 12);
		bool first = true;

		if (gm.json)
			std::cout << "[\n";

		search_commit(rk, gm.shas, suse_users, gm.only_maintainers,
			      [&maintainers, &upstream_maintainers, &has_cves, &first, &cve_hash_map, simple]
			      (const std::string &sha, const std::vector<Person> &sb, const std::set<std::string> &paths) {
			if (gm.trace && !paths.empty()) {
				std::cerr << "SHA " << sha << " contains the following paths: " << std::endl;
				for (const auto &p: paths)
					emit_message('\t', p);
			}
			std::string what;
			if (gm.json) {
				if (!first)
					what = ",\n";
				first = false;
				what += "\t{\n";
				if (has_cves)
					what += "\t\t\"cve\": \"" + cve_hash_map.get_cve(sha) + "\",\n";
				what += "\t\t\"sha\": \"" + sha + "\"";
			} else if (has_cves)
				what = cve_hash_map.get_cve(sha) + "," + sha;
			else
				what = sha;
			if (!sb.empty()) {
				show_people(sb, what, simple);
			} else
				for_all_stanzas(maintainers, upstream_maintainers, paths, simple ? show_emails : gm.json ? json_output : csv_output, what);
		});
		if (gm.json)
			std::cout << "\n]\n";
		return 0;
	}

	SGM_END;
}

namespace {

	void usage(const char *prog, std::ostream &os)
	{
		os << prog << " (version: " SUSE_GET_MAINTAINERS_VERSION ") For more information, read the man page.\n";
		os << "  --help, -h                    - Print this help message\n";
		os << "  --maintainers, -m <file>      - Custom path to the MAINTAINERS file instead of $HOME/.cache/suse-get-maintainers/MAINTAINERS\n";
		os << "  --kernel_tree, -k <dir>       - Clone of the mainline kernel repo ($LINUX_GIT)\n";
		os << "  --vulns, -v <path>            - Path to the clone of https://git.kernel.org/pub/scm/linux/security/vulns.git ($VULNS_GIT)\n";
		os << "  --sha, -s [<sha>|-]...        - SHA of a commit for which we want to find owners; - as stdin batch mode implies CSV output\n";
		os << "                                  this option can be provided multiple times with different values\n";
		os << "                                  SHA could be in shortened form of at least 12 characters\n";
		os << "  --path, -p [<path>|-]...      - Path for which we want to find owners; - as stdin batch mode implies CSV output\n";
		os << "                                  this option can be provided multiple times with different values\n";
		os << "  --diff, -d [<path>|-]...      - Path to a patch we want to find owners; - as stdin batch mode implies CSV output\n";
		os << "                                  this option can be provided multiple times with different values\n";
		os << "  --cve, -c [<CVE number>|-]... - CVE number for which we want to find owners; - as stdin batch mode implies CSV output\n";
		os << "                                  this option can be provided multiple times with different values\n";
		os << "  --all_cves, -C                - Resolve all kernel CVEs and find owners for them; CSV output; use -j or --json option for JSON\n";
		os << "  --rejected, -R                - Query rejected CVEs instead of the published ones.  To be used with -c, -C and -y.\n";
		os << "  --year, -y [year]             - Resolve all kernel CVEs from a given year; CSV output; use -j or --json option for JSON\n";
		os << "  --refresh, -r                 - Refresh MAINTAINERS file and update (fetch origin) $VULNS_GIT and $LINUX_GIT if present\n";
		os << "  --init, -i                    - Clone upstream repositories;  You need to provide at least -k or -v or both!\n";
		os << "  --json, -j                    - Output JSON\n";
		os << "  --csv, -S                     - Output CSV\n";
		os << "  --names, -n                   - Include full names with the emails; by default, just emails are extracted\n";
		os << "  --no_translation, -N          - Do not translate to bugzilla emails\n";
		os << "  --only_maintainers, -M        - Do not analyze the patches/commits; only MAINTAINERS files\n";
		os << "  --trace, -t                   - Be a bit more verbose about how we got there on STDERR\n";
		os << "  --version, -V                 - Print just the version number\n";
	}

	struct option opts[] = {
		{ "help", no_argument, nullptr, 'h' },
		{ "maintainers", required_argument, nullptr, 'm' },
		{ "kernel_tree", required_argument, nullptr, 'k' },
		{ "sha", required_argument, nullptr, 's' },
		{ "path", required_argument, nullptr, 'p' },
		{ "diff", required_argument, nullptr, 'd' },
		{ "vulns", required_argument, nullptr, 'v' },
		{ "cve", required_argument, nullptr, 'c' },
		{ "rejected", no_argument, nullptr, 'R' },
		{ "all_cves", no_argument, nullptr, 'C' },
		{ "year", required_argument, nullptr, 'y' },
		{ "refresh", no_argument, nullptr, 'r' },
		{ "init", no_argument, nullptr, 'i' },
		{ "json", no_argument, nullptr, 'j' },
		{ "csv", no_argument, nullptr, 'S' },
		{ "names", no_argument, nullptr, 'n' },
		{ "trace", no_argument, nullptr, 't' },
		{ "no_translation", no_argument, nullptr, 'N' },
		{ "only_maintainers", no_argument, nullptr, 'M' },
		{ "version", no_argument, nullptr, 'V' },
		{ nullptr, 0, nullptr, 0 },
	};

	void parse_options(int argc, char **argv)
	{
		int c;
		std::string option;

		for (;;) {
			int opt_idx;

			c = getopt_long(argc, argv, "hm:k:s:p:d:v:c:CRy:rijSntNMV", opts, &opt_idx);
			if (c == -1)
				break;

			switch (c) {
			case 'h':
				usage(argv[0], std::cout);
				throw 0;
			case 'm':
				gm.maintainers = optarg;
				break;
			case 'k':
				gm.kernel_tree = optarg;
				break;
			case 's':
				option = optarg;
				if (option == "-")
					gm.from_stdin = true;
				gm.shas.insert(option);
				break;
			case 'p':
				option = optarg;
				if (option == "-")
					gm.from_stdin = true;
				gm.paths.insert(option);
				break;
			case 'd':
				option = optarg;
				if (option == "-")
					gm.from_stdin = true;
				gm.diffs.insert(option);
				break;
			case 'v':
				gm.vulns = optarg;
				break;
			case 'c':
				option = optarg;
				if (option == "-")
					gm.from_stdin = true;
				gm.cves.insert(option);
				break;
			case 'C':
				gm.all_cves = true;
				break;
			case 'R':
				gm.rejected = true;
				break;
			case 'y':
				gm.year = atoi(optarg);
				if (gm.year < 1999 || gm.year > 9999)
					fail_with_message(optarg, " is a year that doesn't make sense for CVE!");
				gm.all_cves = true;
				break;
			case 'r':
				gm.refresh = true;
				break;
			case 'i':
				gm.init = true;
				break;
			case 'j':
				gm.json = true;
				break;
			case 'S':
				gm.csv = true;
				break;
			case 'n':
				gm.names = true;
				break;
			case 't':
				gm.trace = true;
				break;
			case 'N':
				gm.no_translation = true;
				// TODO
				do_not_translate = true;
				// END TODO
				break;
			case 'M':
				gm.only_maintainers = true;
				break;
			case 'V':
				std::cout << SUSE_GET_MAINTAINERS_VERSION << '\n';
				throw 0;
			default:
				usage(argv[0], std::cerr);
				throw 1;
			}
		}
	}

	void show_emails(const Stanza &m, const std::string &)
	{
		m.for_all_maintainers([](const Person &p) {
			if (gm.names && !p.name.empty())
				std::cout << p.name << " <" << p.email << ">\n";
			else
				std::cout << p.email << '\n';
		});
	}

	void csv_output(const Stanza &m, const std::string &what)
	{
		std::cout << what << ',' << '"' << m.name << '"';
		m.for_all_maintainers([](const Person &p) {
			if (gm.names && !p.name.empty())
				std::cout << "," << p.name << " <" << p.email << ">";
			else
				std::cout << "," << p.email;
		});
		std::cout << '\n';
	}

	void json_output(const Stanza &m, const std::string &what)
	{
		std::cout << what << ',' << "\n\t\t\"subsystem\": \"" << m.name << "\",\n\t\t" << "\"emails\": [";
		bool first = true;
		m.for_all_maintainers([&first](const Person &p) {
			if (!first)
				std::cout << ", ";
			first = false;
			if (gm.names && !p.name.empty())
				std::cout << "\"" << p.name << " <" << p.email << ">\"";
			else
				std::cout << "\"" << p.email << "\"";
		});
		std::cout << "]\n\t}";
	}

	void show_people(const std::vector<Person> &sb, const std::string &what, bool simple)
	{

		if (simple) {
			std::set<std::string> duplicate_set;
			for (const Person &p: sb) {
				std::string tmp_email = translate_email(p.email); // TODO
				if (duplicate_set.contains(tmp_email))
					continue;
				duplicate_set.insert(tmp_email);
				if (gm.names)
					std::cout << p.name << " <";
				std::cout << tmp_email; // TODO
				if (gm.names)
					std::cout << ">";
				std::cout << '\n';
			}
		} else if (gm.json) {
			std::cout << what << ','<< "\n\t\t\"roles\": [\"";
			bool first = true;
			for (const Person &p: sb) {
				if (!first)
					std::cout << "\", \"";
				first = false;
                                std::cout << to_string(p.role);
			}
			std::cout << "\"],\n\t\t" << "\"emails\": [\"";
			first = true;
			for (const Person &p: sb) {
				if (!first)
					std::cout << "\", \"";
				first = false;
				std::string tmp_email = translate_email(p.email); // TODO
				if (gm.names)
					std::cout << p.name << " <";
				std::cout << tmp_email; // TODO
				if (gm.names)
					std::cout << ">";
			}
			std::cout << "\"]\n\t}";
		} else {
			std::cout << what << ',' << '"';
			bool first = true;
			for (const Person &p: sb) {
				if (!first)
					std::cout << '/';
				first = false;
				std::cout << to_string(p.role);
			}
			std::cout << '"' << ',';
			first = true;
			for (const Person &p: sb) {
				if (!first)
					std::cout << ',';
				first = false;
				std::string tmp_email = translate_email(p.email); // TODO
				if (gm.names)
					std::cout << p.name << " <";
				std::cout << tmp_email; // TODO
				if (gm.names)
					std::cout << ">";
			}
			std::cout << '\n';
		}
	}

	std::set<std::string> read_stdin_sans_new_lines()
	{
		std::set<std::string> ret;

		for (std::string line; std::getline(std::cin, line);)
			ret.insert(std::string(trim(line)));

		return ret;
	}

	std::optional<const Stanza *> find_best_match(const std::vector<Stanza> &sl, const std::set<std::string> &paths)
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

	template<typename F>
	void for_all_stanzas(const std::vector<Stanza> &suse_stanzas,
			     const std::vector<Stanza> &upstream_stanzas,
			     const std::set<std::string> &paths,
			     F pp,
			     const std::string &what)
	{
		std::optional<const Stanza *> stanza = find_best_match(suse_stanzas, paths);

		if (stanza.has_value()) {
			if (gm.trace)
				std::cerr << "STANZA: " << stanza.value()->name << std::endl;
			pp(*stanza.value(), what);
			return;
		}

		stanza = find_best_match(upstream_stanzas, paths);

		if (stanza.has_value()) {
			if (gm.trace)
				std::cerr << "Upstream STANZA: " << stanza.value()->name << std::endl;
			pp(*stanza.value(), what);
			return;
		}

		thread_local auto catch_all_maintainer = Stanza{"Base", "F: Kernel Developers at SuSE <kernel@suse.de>"};
		if (gm.trace)
			std::cerr << "STANZA: " << catch_all_maintainer.name << std::endl;
		pp(catch_all_maintainer, what);
	}
}
