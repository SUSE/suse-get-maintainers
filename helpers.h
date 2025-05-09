#ifndef SGM_HELPERS_H
#define SGM_HELPERS_H

#include <iostream>
#include <algorithm>
#include <variant>
#include <fstream>
#include <cstdlib>
#include <cstddef>
#include <set>
#include <regex>
#include <cstring>
#include <string_view>
#include <sys/resource.h>

// TODO
#include <unordered_map>
std::unordered_map<std::string, std::string> translation_table;
std::string temporary;
bool do_not_translate = false;
// END TODO

#define SGM_BEGIN try {
#define SGM_END } catch (int ret) { return ret; } catch (...) { return 42; }

#define T_GREEN "\033[01;32m"
#define T_BLUE "\033[01;34m"
#define T_END "\033[0m"

namespace {
	template<typename... Args> void fail_with_message(Args&&... args)
	{
		(std::cerr << ... << args) << std::endl;
		throw 1;
	}

	template<typename... Args> void emit_message(Args&&... args)
	{
		(std::cerr << ... << args) << std::endl;
	}

	bool is_hex(const std::string_view s)
	{
		return std::all_of(s.cbegin(), s.cend(), ::isxdigit);
	}

	std::string_view trim(const std::string_view line)
	{
		static constexpr const char *spaces = " \n\t\r";
		const auto pos1 = line.find_first_not_of(spaces);
		const auto pos2 = line.find_last_not_of(spaces);

		if (pos1 == std::string::npos)
			return std::string("");

		return std::string_view(line).substr(pos1, pos2-pos1+1);
	}

	const std::string sign_offs[] = {
		"Author",
		"Signed-off-by",
		"Co-developed-by",
		"Suggested-by",
		"Reviewed-by",
		"Acked-by",
		"Tested-by",
		"Reported-by",
		"Maintainer",
		"Upstream"
	};

	enum struct Role
	{
		Author,
		SignedOffBy,
		CoDevelopedBy,
		SuggestedBy,
		ReviewedBy,
		AckedBy,
		TestedBy,
		ReportedBy,
		Maintainer,
		Upstream
	};

	std::size_t index(Role r) { return static_cast<std::size_t>(r); }

	std::string to_string(Role r) { return sign_offs[index(r)]; }

	bool is_suse_address(const std::set<std::string> &users, const std::string &email)
	{
		return (email.ends_with("@suse.com") || email.ends_with("@suse.cz") || email.ends_with("@suse.de"))
			&& users.contains(email.substr(0, email.find_first_of("@")));
	}

	bool parse_person(const std::string_view src, std::string &out_name, std::string &out_email)
	{
		std::string_view name, email;
		auto pos = src.find_last_of("@");
		if (pos == std::string::npos)
			return false;
		auto e_sign = src.find_first_of(":");
		if (e_sign == std::string::npos)
			return false;
		++e_sign;
		auto b_mail = src.find_first_of("<", e_sign);
		if (b_mail == std::string::npos)
			if (src.find_first_of(">", e_sign) != std::string::npos)
				return false;
			else {
				email = trim(src.substr(e_sign));
				if (email.find_first_of(" \n\t\r") != std::string::npos)
					return false;
				else {
					out_email = email;
					return true;
				}
			}
		if (b_mail > pos)
			return false;
		name = trim(src.substr(e_sign, b_mail - e_sign));
		if (name.empty())
			return false;
		auto e_mail = src.find_first_of(">", b_mail);
		if (e_mail ==  std::string::npos || e_mail < pos)
			return false;
		email = src.substr(b_mail + 1, e_mail - b_mail - 1);
		if (email.empty())
			return false;
		out_name = name;
		out_email = email;
		return true;
	}

	struct Person
	{
		Person() : role(Role::Maintainer) {}
		Person(Role r) : role(r) {}
		std::string name;
		std::string email;
		Role role;
		bool parse(const std::string &s)
			{
				for (std::size_t i = 1; i < index(Role::TestedBy); ++i) {
					Role r = static_cast<Role>(i);
					if (s.starts_with(to_string(r))) {
						role = r;
						if(parse_person(s, name, email))
							return true;
					}
				}
				return false;
			}
	};

	void validate_cves(const std::set<std::string> &s)
	{
		thread_local const auto regex_cve_number = std::regex("CVE-[0-9][0-9][0-9][0-9]-[0-9]+", std::regex::optimize);
		for (const auto &str: s)
			if (!std::regex_match(str, regex_cve_number))
				emit_message(str, " does not seem to be a valid CVE number");
	}

	std::variant<std::set<std::string>, std::vector<Person>> get_paths_from_patch(const std::string &path, const std::set<std::string>& users, bool skip_signoffs)
	{
		std::variant<std::set<std::string>, std::vector<Person>> ret;
		std::string path_to_patch;

		if (!path.empty() && path[0] != '/') {
			const char *pwd = std::getenv("PWD");
			if (pwd)
				path_to_patch = std::string(pwd) + "/" + path;
		} else
			path_to_patch = path;

		std::ifstream file(path_to_patch);
		if (!file.is_open())
			fail_with_message("Unable to open diff file: ", path_to_patch);

		thread_local const auto regex_add = std::regex("^\\+\\+\\+ [ab]/(.+)", std::regex::optimize);
		thread_local const auto regex_rem = std::regex("^--- [ab]/(.+)", std::regex::optimize);

		std::set<std::string> paths;
		std::vector<Person> people;
		bool signoffs = true;
		std::smatch match;
		for (std::string line; std::getline(file, line); ) {
			line.erase(0, line.find_first_not_of(" \t"));
			if (!skip_signoffs && signoffs) {
				if (line.starts_with("From") || line.starts_with("Author")) {
					Person a{Role::Author};
					if (parse_person(line, a.name, a.email) && is_suse_address(users, a.email))
						people.push_back(std::move(a));
				}
				Person p;
				if (p.parse(line) && is_suse_address(users, p.email))
					people.push_back(std::move(p));
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

	void try_to_fetch_env(std::string &var, const std::string &name)
	{
		if (var.empty()) {
			const char *ptr = std::getenv(name.c_str());
			if (ptr)
				var = ptr;
		}
	}

	template <typename T>
	std::string color_format(bool b, const std::string &c, const T &s)
	{
		std::stringstream ret;
		if (b)
			ret << c;
		ret << s;
		if (b)
			ret << T_END;
		return ret.str();
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
		if (ret.empty()) {
			fail_with_message("The subsystem name \"" + s + "\" is so bizarre that it ended up being empty!");
			throw 1;
		}
		return ret;
	}

	std::size_t get_soft_limit_for_opened_files(std::size_t min_limit)
	{
		struct rlimit rl;
		if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
			if (rl.rlim_cur < min_limit)
				fail_with_message("RLIMIT_NOFILE is less than ", min_limit, ".  Please bump it!");
			return rl.rlim_cur;
		}
		emit_message("getrlimit");
		return 1024;
	}

	// TODO
	std::string translate_email(std::string_view sv)
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
}

#endif
