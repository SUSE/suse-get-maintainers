#ifndef SGM_GITHELPERS_H
#define SGM_GITHELPERS_H

#include <functional>
#include <iostream>
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

	static void validateShas(std::set<std::string> &s, std::size_t min)
	{
		for (auto &str: s)
			if (!SlHelpers::String::isHex(str) || (str.size() > 40 || str.size() < min))
				std::cerr << str <<
					     " does not seem to be a SHA hash of at least " <<
					     min << " characters long\n";
	}

	static void searchCommit(const SlGit::Repo &repo,
				 const std::set<std::string> &shas,
				 bool skip_signoffs, bool trace,
				 const SearchCallback &pp);

private:
	static std::vector<Person> getSomebodyElse(const SlGit::Commit &commit);
};

}

#endif
