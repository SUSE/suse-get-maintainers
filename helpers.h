#ifndef SGM_HELPERS_H
#define SGM_HELPERS_H

#include <iostream>
#include <cstdlib>
#include <cstddef>
#include <set>
#include <cstring>
#include <string_view>
#include <sys/resource.h>

#include <sl/helpers/String.h>

// TODO
#include <unordered_map>
std::unordered_map<std::string, std::string> translation_table;
bool do_not_translate = false;
// END TODO

#define SGM_BEGIN try {
#define SGM_END } catch (int ret) { return ret; } catch (...) { return 42; }

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

	struct NonCopyable
	{
		NonCopyable() = default;
		NonCopyable(const NonCopyable&) = delete;
		NonCopyable& operator=(const NonCopyable&) = delete;
	};

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

	bool is_suse_address([[maybe_unused]] const std::set<std::string> &users, const std::string &email)
	{
		return (email.ends_with("@suse.com") || email.ends_with("@suse.cz") || email.ends_with("@suse.de"));
		//&& users.contains(email.substr(0, email.find_first_of("@")));
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
				email = SlHelpers::String::trim(src.substr(e_sign));
				if (email.find_first_of(" \n\t\r") != std::string::npos)
					return false;
				else {
					out_email = email;
					return true;
				}
			}
		if (b_mail > pos)
			return false;
		name = SlHelpers::String::trim(src.substr(e_sign, b_mail - e_sign));
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
		Person() : role(Role::Maintainer), count(0) {}
		Person(Role r) : role(r), count(0) {}
		std::string name;
		std::string email;
		Role role;
		int count;
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

	template <typename T>
	void try_to_fetch_env(T &var, const std::string &name)
	{
		if (var.empty()) {
			const char *ptr = std::getenv(name.c_str());
			if (ptr)
				var = ptr;
		}
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
