#ifndef SGM_HELPERS_H
#define SGM_HELPERS_H

#include <iostream>
#include <cstdlib>
#include <set>
#include <sys/resource.h>

#include <sl/helpers/String.h>

#define SGM_BEGIN try {
#define SGM_END } catch (int ret) { return ret; } catch (...) { return 42; }

namespace {
	template<typename... Args> void fail_with_message(Args&&... args)
	{
		(std::cerr << ... << args) << std::endl;
		throw 1;
	}

	bool is_suse_address([[maybe_unused]] const std::set<std::string> &users, const std::string &email)
	{
		return (email.ends_with("@suse.com") || email.ends_with("@suse.cz") || email.ends_with("@suse.de"));
		//&& users.contains(email.substr(0, email.find_first_of("@")));
	}
}

#endif
