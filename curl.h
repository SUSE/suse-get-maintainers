#ifndef SGM_CURL_H
#define SGM_CURL_H

#include <ctime>
#include <sys/stat.h>
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
		PageFile(const std::string &path)
			{
				m_pagefile = std::fopen(path.c_str(), "wb");
			}
		~PageFile() { std::fclose(m_pagefile); }
		FILE *get() const { return m_pagefile; }
		operator bool() const { return m_pagefile != nullptr; }
	private:
		FILE* m_pagefile;
	};

	std::string fetch_file_if_needed(std::string maintainers_path, const std::string &name, const std::string &url, bool trace, bool refresh, bool ignore_errors, int hours)
	{
		if (!maintainers_path.empty())
			return maintainers_path;

		const char *xdg_cache_dir = std::getenv("XDG_CACHE_HOME");
		if(xdg_cache_dir)
			maintainers_path = xdg_cache_dir;
		else {
			const char *home_dir = std::getenv("HOME");
			if(home_dir)
				maintainers_path = home_dir;
			else
				fail_with_message("Unable to open HOME directory!");
			maintainers_path += "/.cache";
		}
		struct stat sb;
		if (stat(maintainers_path.c_str(), &sb) == -1)
			if(mkdir(maintainers_path.c_str(), 0755))
				fail_with_message("Unable to create .cache directory!");
		maintainers_path += "/suse-get-maintainers";
		if (stat(maintainers_path.c_str(), &sb) == -1)
			if (mkdir(maintainers_path.c_str(), 0755))
				fail_with_message("Unable to locate .cache/suse-get-maintainers directory!");

		maintainers_path.push_back('/');
		maintainers_path += name;

		bool file_already_exists = false;
		if (stat(maintainers_path.c_str(), &sb) == 0) {
			file_already_exists = true;
			if (!refresh) {
				struct timespec current_time;
				timespec_get(&current_time, TIME_UTC);

				const decltype(current_time.tv_sec) expires_after_seconds = 60 * 60 * hours;
				decltype(current_time.tv_sec) time_diff = current_time.tv_sec - sb.st_mtim.tv_sec;
				if (time_diff < expires_after_seconds)
					return maintainers_path;
			}
		}
		if (trace || refresh)
			emit_message("Downloading... ", maintainers_path, " from ", url);

		LibCurl libcurl;
		CurlHandle curl_handle;
		curl_handle.set_url(url);

		const std::string new_path = maintainers_path + ".NEW";
		PageFile pagefile(new_path);
		if (pagefile) {
			curl_easy_setopt(curl_handle.get(), CURLOPT_WRITEDATA, pagefile.get());
			if (curl_easy_perform(curl_handle.get())) {
				if (ignore_errors)
					return "";
				emit_message("Failed to fetch ", name, " from ", url, " to ", maintainers_path);
				if (file_already_exists)
					return maintainers_path;
				else
					throw 1;
			}
			long http_code = 0;
			curl_easy_getinfo(curl_handle.get(), CURLINFO_RESPONSE_CODE, &http_code);
			if (http_code >= 400) {
				if (ignore_errors)
					return "";
				emit_message("Failed to fetch ", name," (", http_code, ") from ", url, " to ", maintainers_path);
				if (file_already_exists)
					return maintainers_path;
				else
					throw 1;
			}
			rename(new_path.c_str(), maintainers_path.c_str());
		}
		return maintainers_path;
	}
}

#endif
