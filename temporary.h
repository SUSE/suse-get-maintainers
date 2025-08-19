#ifndef SGM_TEMPORARY_H
#define SGM_TEMPORARY_H

#include <fstream>
#include <string>
#include <string_view>
#include <unordered_map>

#include "helpers.h"

namespace {
	void load_temporary(std::unordered_map<std::string, std::string> &h, const std::string &filename)
	{
		std::ifstream file{filename};

		if (!file.is_open())
			fail_with_message("Unable to open user-bugzilla-map.txt file: ", filename);

		for (std::string line; getline(file, line);) {
			if (line.empty() || line[0] == ';' || line[0] == ' ')
				continue;
			const auto equal_sign_idx = line.find_first_of("=");
			if (equal_sign_idx == std::string::npos) {
				emit_message("user-bugzilla-map.txt: ", line);
				continue;
			}
			std::string_view user = trim(std::string_view(line).substr(0, equal_sign_idx));
			std::string_view bz_user = trim(std::string_view(line).substr(equal_sign_idx + 1));
			if (user.empty() || bz_user.empty()) {
				emit_message("user-bugzilla-map.txt: ", line);
				continue;
			}
			h.insert(std::make_pair(user, bz_user));
		}
	}
}

#endif
