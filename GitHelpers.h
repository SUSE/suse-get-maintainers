#ifndef SGM_GITHELPERS_H
#define SGM_GITHELPERS_H

#include <functional>
#include <string>
#include <set>

#include <sl/git/Commit.h>
#include <sl/git/Repo.h>
#include <sl/helpers/String.h>
#include <sl/kerncvs/Person.h>

#include "PathsOrPeople.h"

namespace SGM {

class GitHelpers {
public:
	using SearchCallback = std::function<void (std::string sha, PathsOrPeople pop)>;

	static void searchCommit(const SlGit::Repo &repo,
				 const std::set<std::string> &shas,
				 bool skip_signoffs, bool trace,
				 const SearchCallback &pp);

private:
	static std::vector<SlKernCVS::Person> getSomebodyElse(const SlGit::Commit &commit);
};

}

#endif
