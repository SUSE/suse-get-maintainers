#ifndef SGM_GITHELPERS_H
#define SGM_GITHELPERS_H

#include <functional>
#include <string>
#include <set>

#include <sl/git/Git.h>
#include <sl/helpers/String.h>

#include "Person.h"

namespace SGM {

class GitHelpers {
public:
	using SearchCallback = std::function<void (const std::string &, const std::vector<Person> &,
						   const std::set<std::filesystem::path> &)>;

	static void searchCommit(const SlGit::Repo &repo,
				 const std::set<std::string> &shas,
				 bool skip_signoffs, bool trace,
				 const SearchCallback &pp);

private:
	static std::vector<Person> getSomebodyElse(const SlGit::Commit &commit);
};

}

#endif
