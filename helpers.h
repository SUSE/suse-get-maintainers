#ifndef SGM_HELPERS_H
#define SGM_HELPERS_H

#include <iostream>
#include <sys/resource.h>

#define SGM_BEGIN try {
#define SGM_END } catch (int ret) { return ret; } catch (...) { return 42; }

namespace {
	template<typename... Args> void fail_with_message(Args&&... args)
	{
		(std::cerr << ... << args) << std::endl;
		throw 1;
	}
}

#endif
