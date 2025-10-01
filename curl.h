#ifndef SGM_CURL_H
#define SGM_CURL_H

#include <filesystem>
#include <string>

#include <curl/curl.h>

#include "helpers.h"

namespace
{
	struct LibCurl : NonCopyable
	{
		LibCurl()
			{
				if (curl_global_init(CURL_GLOBAL_ALL))
					fail_with_message("Failed to initilize libcurl!");
			}
		~LibCurl() { curl_global_cleanup(); }
	};

	struct CurlHandle : NonCopyable
	{
		CurlHandle()
			{
				if ((m_curl_handle = curl_easy_init()) == nullptr)
					fail_with_message("Failed to get curl_handle!!");
				curl_easy_setopt(m_curl_handle, CURLOPT_NOPROGRESS, 1L);
				curl_easy_setopt(m_curl_handle, CURLOPT_WRITEFUNCTION, ::fwrite);
				curl_easy_setopt(m_curl_handle, CURLOPT_FAILONERROR, 1L);
			}
		~CurlHandle() { curl_easy_cleanup(m_curl_handle); }
		void set_url(const std::string &url) { curl_easy_setopt(m_curl_handle, CURLOPT_URL, url.c_str()); }
		CURL *get() const { return m_curl_handle; }
	private:
		CURL *m_curl_handle;
	};

	struct PageFile : NonCopyable
	{
		PageFile(const std::filesystem::path &path)
			{
				m_pagefile = std::fopen(path.c_str(), "wb");
			}
		~PageFile() { std::fclose(m_pagefile); }
		FILE *get() const { return m_pagefile; }
		operator bool() const { return m_pagefile != nullptr; }
	private:
		FILE* m_pagefile;
	};

	static inline std::filesystem::path get_cache_dir()
	{
		const auto xdg_cache_dir = std::getenv("XDG_CACHE_HOME");
		if (xdg_cache_dir)
			return xdg_cache_dir;

		const auto home_dir = std::getenv("HOME");
		if (!home_dir)
			fail_with_message("Unable to open HOME directory!");

		return std::filesystem::path(home_dir) / ".cache";
	}

	static inline std::filesystem::path get_maintainers_cache_dir()
	{
		const auto cache = get_cache_dir() / "suse-get-maintainers";
		std::filesystem::create_directories(cache);
		return cache;
	}

	static inline bool is_download_needed(const std::filesystem::path &file_path,
					      bool &file_already_exists, bool force_refresh,
					      const std::chrono::hours &hours)
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

	static inline std::filesystem::path fetch_file_if_needed(const std::filesystem::path &existing_path,
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

		LibCurl libcurl;
		CurlHandle curl_handle;
		curl_handle.set_url(url);

		auto new_path(file_path);
		new_path += ".NEW";
		PageFile pagefile(new_path);
		if (pagefile) {
			curl_easy_setopt(curl_handle.get(), CURLOPT_WRITEDATA, pagefile.get());
			if (curl_easy_perform(curl_handle.get())) {
				if (ignore_errors)
					return "";
				emit_message("Failed to fetch ", name, " from ", url, " to ", file_path);
				if (file_already_exists)
					return file_path;
				else
					throw 1;
			}
			long http_code = 0;
			curl_easy_getinfo(curl_handle.get(), CURLINFO_RESPONSE_CODE, &http_code);
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
		}
		return file_path;
	}
}

#endif
