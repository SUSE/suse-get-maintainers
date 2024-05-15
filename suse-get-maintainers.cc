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

namespace {
	void parse_options(int argc, char **argv);
	void fetch_repo(const std::string &, const std::string &);
	void show_emails(const Stanza &m, const std::string&);
	void csv_output(const Stanza &m, const std::string&);
	void json_output(const Stanza &m, const std::string&);
	void show_person(const Person &, const std::string &, bool);
	std::set<std::string> read_stdin_sans_new_lines();
	void for_all_stanzas(const std::vector<Stanza> &,
			     const std::vector<Stanza> &,
			     const std::set<std::string> &,
			     std::function<void(const Stanza &, const std::string &)>,
			     const std::string &);

	struct gm {
		gm() : year(0), rejected(false), all_cves(false), json(false), names(false), from_stdin(false), trace(false), refresh(false), init(false) {}

		std::string maintainers;
		std::string kernel_tree;
		std::set<std::string> shas;
		std::set<std::string> paths;
		std::set<std::string> diffs;
		std::string vulns;
		std::set<std::string> cves;
		int year;
		bool rejected;
		bool all_cves;
		bool json;
		bool names;
		bool from_stdin;
		bool trace;
		bool refresh;
		bool init;
	} gm;
}

int main(int argc, char **argv)
{
	SGM_BEGIN;

	LibGit2 libgit2_state;
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

		if (gm.paths.size() > 1 || gm.from_stdin) {
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
				std::cout << "\n]" << std::endl;
		} else
			for_all_stanzas(maintainers, upstream_maintainers, gm.paths, show_emails, "");
		return 0;
	}

	if (!gm.diffs.empty()) {
		if (gm.from_stdin)
			gm.diffs = read_stdin_sans_new_lines();

		if (gm.diffs.size() > 1 || gm.from_stdin) {
			if (gm.json)
				std::cout << "[\n";
			bool first = true;
			for (const auto &ps: gm.diffs) {
				try {
					std::variant<std::set<std::string>, Person> s = get_paths_from_patch(ps, suse_users);
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
					if (std::holds_alternative<Person>(s)) {
						const Person sb = std::get<Person>(s);
						if (gm.trace)
							emit_message("We have ", sb.role == Role::Author || sb.role == Role::AckedBy
								     ? "an " : "a ", to_string(sb.role));
						show_person(sb, what, false);
					} else
						for_all_stanzas(maintainers, upstream_maintainers, std::get<std::set<std::string>>(s), gm.json ? json_output : csv_output, what);
				} catch (...) { continue; }
			}
			if (gm.json)
				std::cout << "\n]" << std::endl;
		} else {
			std::variant<std::set<std::string>, Person> s = get_paths_from_patch(*gm.diffs.cbegin(), suse_users);
			if (gm.trace && std::holds_alternative<std::set<std::string>>(s)) {
				std::cerr << "patch " << *gm.diffs.cbegin() << " contains the following paths: " << std::endl;
				for (const auto &p: std::get<std::set<std::string>>(s))
					std::cerr << '\t' << p << std::endl;
			}
			if (std::holds_alternative<Person>(s)) {
				const Person sb = std::get<Person>(s);
				if (gm.trace)
					emit_message("We have ", sb.role == Role::Author || sb.role == Role::AckedBy
						     ? "an " : "a ", to_string(sb.role));
				show_person(sb, "", true);
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

		bool simple;
		if (gm.shas.size() == 1 && gm.from_stdin && !has_cves) {
			gm.shas = read_stdin_sans_new_lines();
			simple = false;
		} else if (gm.shas.size() > 1 || (gm.shas.size() == 1 && gm.from_stdin && has_cves)) {
			simple = false;
		} else {
			simple = true;
			gm.json = false;
		}

		validate_shas(gm.shas, has_cves ? 40 : 12);
		bool first = true;

		if (gm.json)
			std::cout << "[\n";

		search_commit(rk, gm.shas, suse_users,
			      [&maintainers, &upstream_maintainers, &has_cves, &first, &cve_hash_map, simple]
			      (const std::string &sha, const Person &sb, const std::set<std::string> &paths) {
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
			if (sb.role != Role::Maintainer) {
				if (gm.trace)
					emit_message("We have ", sb.role == Role::Author || sb.role == Role::AckedBy ? "an " : "a ", to_string(sb.role));
				show_person(sb, what, simple);
			} else
				for_all_stanzas(maintainers, upstream_maintainers, paths, simple ? show_emails : gm.json ? json_output : csv_output, what);
		});
		if (gm.json)
			std::cout << "\n]" << std::endl;
		return 0;
	}

	SGM_END;
}

namespace {

	void usage(const char *prog, std::ostream &os)
	{
		os << prog << " (version: " SUSE_GET_MAINTAINERS_VERSION ") For more information, read the man page." << std::endl;
		os << "  --help, -h                    - Print this help message" << std::endl;
		os << "  --maintainers, -m <file>      - Custom path to the MAINTAINERS file instead of $HOME/.cache/suse-get-maintainers/MAINTAINERS" << std::endl;
		os << "  --kernel_tree, -k <dir>       - Clone of the mainline kernel repo ($LINUX_GIT)" << std::endl;
		os << "  --vulns, -v <path>            - Path to the clone of https://git.kernel.org/pub/scm/linux/security/vulns.git ($VULNS_GIT)" << std::endl;
		os << "  --sha, -s [<sha>|-]...        - SHA of a commit for which we want to find owners; - as stdin batch mode implies CSV output" << std::endl;
		os << "                                  this option can be provided multiple times with different values" << std::endl;
		os << "                                  SHA could be in shortened form of at least 12 characters" << std::endl;
		os << "  --path, -p [<path>|-]...      - Path for which we want to find owners; - as stdin batch mode implies CSV output" << std::endl;
		os << "                                  this option can be provided multiple times with different values" << std::endl;
		os << "  --diff, -d [<path>|-]...      - Path to a patch we want to find owners; - as stdin batch mode implies CSV output" << std::endl;
		os << "                                  this option can be provided multiple times with different values" << std::endl;
		os << "  --cve, -c [<CVE number>|-]... - CVE number for which we want to find owners; - as stdin batch mode implies CSV output" << std::endl;
		os << "                                  this option can be provided multiple times with different values" << std::endl;
		os << "  --all_cves, -C                - Resolve all kernel CVEs and find owners for them; CSV output; use -j or --json option for JSON" << std::endl;
		os << "  --rejected, -R                - Query rejected CVEs instead of the published ones.  To be used with -c, -C and -y." << std::endl;
		os << "  --year, -y [year]             - Resolve all kernel CVEs from a given year; CSV output; use -j or --json option for JSON" << std::endl;
		os << "  --refresh, -r                 - Refresh MAINTAINERS file and update (fetch origin) $VULNS_GIT and $LINUX_GIT if present" << std::endl;
		os << "  --init, -i                    - Clone upstream repositories;  You need to provide at least -k or -v or both!" << std::endl;
		os << "  --json, -j                    - Output JSON instead of CSV in batch mode; nop otherwise" << std::endl;
		os << "  --names, -n                   - Include full names with the emails; by default, just emails are extracted" << std::endl;
		os << "  --trace, -t                   - Be a bit more verbose about how we got there on STDERR" << std::endl;
		os << "  --version, -V                 - Print just the version number" << std::endl;
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
		{ "names", no_argument, nullptr, 'n' },
		{ "trace", no_argument, nullptr, 't' },
		{ "version", no_argument, nullptr, 'V' },
		{ nullptr, 0, nullptr, 0 },
	};

	void parse_options(int argc, char **argv)
	{
		int c;
		std::string option;

		for (;;) {
			int opt_idx;

			c = getopt_long(argc, argv, "hm:k:s:p:d:v:c:CRy:rijntV", opts, &opt_idx);
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
			case 'n':
				gm.names = true;
				break;
			case 't':
				gm.trace = true;
				break;
			case 'V':
				std::cout << SUSE_GET_MAINTAINERS_VERSION << std::endl;
				throw 0;
			default:
				usage(argv[0], std::cerr);
				throw 1;
			}
		}
	}

	void fetch_repo(const std::string &repo_path, const std::string &name)
	{
		emit_message("Trying to fetch... ", name, " in ", repo_path);
		Repo repo;
		if (repo.from_path(repo_path))
			fail_with_message(git_error_last()->message);

		Remote remote;
		if (remote.from_name(repo, name))
			fail_with_message(git_error_last()->message);

		if (remote.fetch())
			fail_with_message(git_error_last()->message);

		remote.print_stats();
	}

	void show_emails(const Stanza &m, const std::string &)
	{
		m.for_all_maintainers([](const Person &p) {
			if (gm.names && !p.name.empty())
				std::cout << p.name << " <" << p.email << ">" << std::endl;
			else
				std::cout << p.email << std::endl;
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
		std::cout << std::endl;
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

	void show_person(const Person &sb, const std::string &what, bool simple)
	{
		if (simple) {
			if (gm.names)
				std::cout << sb.name << " <";
			std::cout << sb.email;
			if (gm.names)
				std::cout << ">";
			std::cout << std::endl;
		} else if (gm.json) {
			std::cout << what << ',' << "\n\t\t\"role\": \"" << to_string(sb.role) << "\",\n\t\t" << "\"email\": \"";
			if (gm.names)
				std::cout << sb.name << " <";
			std::cout << sb.email;
			if (gm.names)
				std::cout << ">\"";
			std::cout << "\n\t}";
		} else {
			std::cout << what << ',' << '"' << to_string(sb.role) << '"' << ',';
			if (gm.names)
				std::cout << sb.name << " <";
			std::cout << sb.email;
			if (gm.names)
				std::cout << ">";
			std::cout << std::endl;
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

	void for_all_stanzas(const std::vector<Stanza> &suse_stanzas,
			     const std::vector<Stanza> &upstream_stanzas,
			     const std::set<std::string> &paths,
			     std::function<void(const Stanza &, const std::string &)> pretty_printer,
			     const std::string &what)
	{
		std::optional<const Stanza *> stanza = find_best_match(suse_stanzas, paths);

		if (stanza.has_value()) {
			if (gm.trace)
				std::cerr << "STANZA: " << stanza.value()->name << std::endl;
			pretty_printer(*stanza.value(), what);
			return;
		}

		stanza = find_best_match(upstream_stanzas, paths);

		if (stanza.has_value()) {
			if (gm.trace)
				std::cerr << "Upstream STANZA: " << stanza.value()->name << std::endl;
			pretty_printer(*stanza.value(), what);
			return;
		}

		thread_local auto catch_all_maintainer = Stanza{"Base", "F: Kernel Developers at SuSE <kernel@suse.de>"};
		if (gm.trace)
			std::cerr << "STANZA: " << catch_all_maintainer.name << std::endl;
		pretty_printer(catch_all_maintainer, what);
	}
}
