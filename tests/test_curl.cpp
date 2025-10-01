#include <cassert>

#include "curl.h"

using namespace std::chrono_literals;

static void test_is_download_needed()
{
	std::filesystem::path tmp_file{std::tmpnam(nullptr)};
	bool exists = false;

	std::cout << __func__ << ": " << tmp_file << '\n';

	assert(is_download_needed(tmp_file, exists, true, 1h));
	assert(!exists);
	assert(is_download_needed(tmp_file, exists, false, 1h));
	assert(!exists);

	std::ofstream ofs{tmp_file};
	assert(is_download_needed(tmp_file, exists, true, 1h));
	assert(exists);
	assert(!is_download_needed(tmp_file, exists, false, 1h));
	assert(exists);

	std::filesystem::last_write_time(tmp_file,
					 std::filesystem::file_time_type::clock::now() - 2h);
	assert(is_download_needed(tmp_file, exists, false, 1h));
	assert(!is_download_needed(tmp_file, exists, false, 3h));

	std::filesystem::remove(tmp_file);
}

static void restore_env(const std::string &env, const char *orig)
{
	if (orig)
		setenv(env.c_str(), orig, true);
	else
		unsetenv(env.c_str());
}

static void test_cache_dirs()
{
	auto orig_xdg = std::getenv("XDG_CACHE_HOME");
	auto orig_home = std::getenv("HOME");

	setenv("XDG_CACHE_HOME", "/xdg_cache", true);
	setenv("HOME", "/home_dir/user/", true);
	assert(get_cache_dir() == "/xdg_cache");
	unsetenv("XDG_CACHE_HOME");
	assert(get_cache_dir() == "/home_dir/user/.cache");

	restore_env("XDG_CACHE_HOME", orig_xdg);
	restore_env("HOME", orig_home);
}

static void test_get_maintainers_cache_dir()
{
	auto orig_xdg = std::getenv("XDG_CACHE_HOME");
	auto orig_home = std::getenv("HOME");

	std::filesystem::path tmp_dir{std::tmpnam(nullptr)};
	std::filesystem::create_directories(tmp_dir);
	std::cout << __func__ << ": " << tmp_dir << '\n';

	unsetenv("XDG_CACHE_HOME");
	setenv("HOME", tmp_dir.c_str(), true);
	auto cache_dir = get_maintainers_cache_dir();
	auto assumed_dir = tmp_dir / ".cache/suse-get-maintainers";
	assert(cache_dir == assumed_dir);
	assert(std::filesystem::exists(assumed_dir));

	restore_env("XDG_CACHE_HOME", orig_xdg);
	restore_env("HOME", orig_home);

	std::filesystem::remove_all(tmp_dir);
}

#ifndef HAS_CONNECTION
#define HAS_CONNECTION	0
#endif

static void test_fetch_file_if_needed()
{
	if (!HAS_CONNECTION)
		return;
	std::cout << "trial: " << fetch_file_if_needed({}, "trial",
						     "https://kerncvs.suse.de/MAINTAINERS",
						     true, false, false, 1h) << '\n';
}

int main()
{
	test_is_download_needed();
	test_cache_dirs();
	test_get_maintainers_cache_dir();
	test_fetch_file_if_needed();

	return 0;
}
