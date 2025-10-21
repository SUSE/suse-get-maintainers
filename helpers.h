#ifndef SGM_HELPERS_H
#define SGM_HELPERS_H

#include <iostream>
#include <cstdlib>
#include <set>
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

	bool is_suse_address([[maybe_unused]] const std::set<std::string> &users, const std::string &email)
	{
		return (email.ends_with("@suse.com") || email.ends_with("@suse.cz") || email.ends_with("@suse.de"));
		//&& users.contains(email.substr(0, email.find_first_of("@")));
	}

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
