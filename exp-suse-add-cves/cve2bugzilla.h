#ifndef SGM_CVE2BUGZILLA_H
#define SGM_CVE2BUGZILLA_H

#include <unordered_map>
#include <string>
#include <string_view>
#include <fstream>
#include <iostream>

#include "helpers.h"

namespace {
	struct CVE2Bugzilla {
		CVE2Bugzilla() {}

		bool load(const std::string &cve2bugzilla);
		std::string get_bsc(const std::string &cve_number) const;
		std::string get_cve(const std::string &bsc_number) const;
	private:
		std::unordered_map<std::string, std::string> m_cve_bsc_map;
		std::unordered_map<std::string, std::string> m_bsc_cve_map;
	};

	bool CVE2Bugzilla::load(const std::string &cve2bugzilla)
	{
		std::ifstream file{cve2bugzilla};

		if (!file.is_open())
			fail_with_message("Unable to open cve2bugzilla.txt file: ", cve2bugzilla);

		for (std::string line; getline(file, line);) {
			if (line.find("EMBARGOED") != std::string::npos
			    || line.find("BUGZILLA:") == std::string::npos || line.find("CVE") == std::string::npos)
				continue;
			const auto cve_end_idx = line.find_first_of(",");
			const auto bsc_begin_idx = line.find_first_of(":");
			if (cve_end_idx == std::string::npos
			    || cve_end_idx < 10
			    || bsc_begin_idx == std::string::npos
			    || bsc_begin_idx + 1 == std::string::npos) {
				emit_message("user-bugzilla-map.txt: ", line);
				continue;
			}
			std::string_view cve_number = trim(std::string_view(line).substr(0, cve_end_idx));
			std::string_view bsc_number = trim(std::string_view(line).substr(bsc_begin_idx + 1));
			if (cve_number.empty() || bsc_number.empty()) {
				emit_message("user-bugzilla-map.txt: ", line);
				continue;
			}
			std::string bug{"bsc#"};
			bug += bsc_number;
			m_cve_bsc_map.insert(std::make_pair(cve_number, bug));
			m_bsc_cve_map.insert(std::make_pair(std::move(bug), cve_number));
		}

		return true;
	}

	std::string CVE2Bugzilla::get_bsc(const std::string &cve_number) const
	{
		const auto it = m_cve_bsc_map.find(cve_number);
		if (it != m_cve_bsc_map.cend())
			return it->second;

		return std::string();
	}

	std::string CVE2Bugzilla::get_cve(const std::string &bsc_number) const
	{
		const auto it = m_bsc_cve_map.find(bsc_number);
		if (it != m_bsc_cve_map.cend())
			return it->second;

		return std::string();
	}
}
#endif
