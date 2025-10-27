#ifndef SGM_MAINTAINERS_H
#define SGM_MAINTAINERS_H

#include <filesystem>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <sl/git/Repo.h>
#include <sl/helpers/String.h>

#include "Stanza.h"

namespace SGM {

class Maintainers {
public:
	using MaintainersType = std::vector<Stanza>;

	static std::optional<Maintainers> load(const std::filesystem::path &SUSE,
					       const std::filesystem::path &linuxRepo,
					       const std::string &origin,
					       const Stanza::TranslateEmail &translateEmail) {
		Maintainers m;

		if (!m.loadSUSE(SUSE, translateEmail))
			return std::nullopt;
		if (!linuxRepo.empty() && !m.loadUpstream(linuxRepo, origin, translateEmail))
			return std::nullopt;

		return m;
	}

	const Stanza *findBestMatch(const std::set<std::filesystem::path> &paths) const {
		return findBestMatchInMaintainers(m_maintainers, paths);
	}
	const Stanza *findBestMatchUpstream(const std::set<std::filesystem::path> &paths) const {
		return findBestMatchInMaintainers(m_upstream_maintainers, paths);
	}

	const MaintainersType &maintainers() const { return m_maintainers; }
	const MaintainersType &upstream_maintainers() const { return m_upstream_maintainers; }
	const std::set<std::string> &suse_users() const { return m_suse_users; }
private:
	Maintainers() {}

	bool loadSUSE(const std::filesystem::path &filename,
		      const Stanza::TranslateEmail &translateEmail);
	bool loadUpstream(const std::filesystem::path &lsource, const std::string &origin,
			  const Stanza::TranslateEmail &translateEmail);

	static const Stanza *findBestMatchInMaintainers(const MaintainersType &sl,
							const std::set<std::filesystem::path> &paths);

	MaintainersType m_maintainers;
	MaintainersType m_upstream_maintainers;
	std::set<std::string> m_suse_users;
};

}

#endif
