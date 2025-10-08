#ifndef SGM_CURL_H
#define SGM_CURL_H

#include <filesystem>
#include <string>

#include <sl/curl/Curl.h>

#include "helpers.h"

namespace
{
	std::filesystem::path get_cache_dir()
	{
		const auto xdg_cache_dir = std::getenv("XDG_CACHE_HOME");
		if (xdg_cache_dir)
			return xdg_cache_dir;

		const auto home_dir = std::getenv("HOME");
		if (!home_dir)
			fail_with_message("Unable to open HOME directory!");

		return std::filesystem::path(home_dir) / ".cache";
	}

	std::filesystem::path get_maintainers_cache_dir()
	{
		const auto cache = get_cache_dir() / "suse-get-maintainers";
		std::filesystem::create_directories(cache);
		return cache;
	}

	bool is_download_needed(const std::filesystem::path &file_path, bool &file_already_exists,
				bool force_refresh, const std::chrono::hours &hours)
	{
		if (!std::filesystem::exists(file_path))
			return true;

		file_already_exists = true;
		if (force_refresh)
			return true;

		const auto mtime = std::filesystem::last_write_time(file_path);
		const auto now = std::filesystem::file_time_type::clock::now();

		return mtime < now - hours;
	}

	std::filesystem::path fetch_file_if_needed(const std::filesystem::path &existing_path,
						   const std::filesystem::path &name,
						   const std::string &url,
						   bool trace, bool force_refresh,
						   bool ignore_errors,
						   const std::chrono::hours &hours)
	{
		if (!existing_path.empty())
			return existing_path;

		auto file_path = get_maintainers_cache_dir() / name;

		bool file_already_exists = false;
		if (!is_download_needed(file_path, file_already_exists, force_refresh, hours))
			return file_path;

		if (trace || force_refresh)
			emit_message("Downloading... ", file_path, " from ", url);

		auto new_path(file_path);
		new_path += ".NEW";
		unsigned http_code;
		if (!SlCurl::LibCurl::singleDownloadToFile(url, new_path, &http_code)) {
			if (ignore_errors)
				return "";
			emit_message("Failed to fetch ", name, " from ", url, " to ", file_path);
			if (file_already_exists)
				return file_path;
			else
				throw 1;
		}
		if (http_code >= 400) {
			if (ignore_errors)
				return "";
			emit_message("Failed to fetch ", name," (", http_code, ") from ", url, " to ", file_path);
			if (file_already_exists)
				return file_path;
			else
				throw 1;
		}
		std::filesystem::rename(new_path, file_path);

		return file_path;
	}
}

#endif
