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
				 const std::set<std::string> &suse_users,
				 bool skip_signoffs, bool trace,
				 const SearchCallback &pp);

private:
	static std::vector<Person> getSomebodyElse(const SlGit::Commit &commit,
						   const std::set<std::string> &users);
	static void simpleTreeEntryAdd(const SlGit::TreeEntry &e, const SlGit::Repo &repo,
				       std::set<std::filesystem::path> &paths,
				       const std::string &prefix,
				       const std::string &name);

	static void simpleTreeEntryDiff(const std::string &name, const SlGit::Repo &repo,
					const SlGit::TreeEntry &a, const SlGit::TreeEntry &b,
					std::set<std::filesystem::path> &paths,
					const std::string &prefix);

	static void simpleTreeDiff(const SlGit::Repo &repo, const SlGit::Tree &pt,
				   const SlGit::Tree &ct, std::set<std::filesystem::path> &paths,
				   const std::string &prefix = std::string());
};

}

#endif
