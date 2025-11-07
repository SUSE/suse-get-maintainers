#include <sl/git/Commit.h>
#include <sl/helpers/Color.h>
#include <sl/helpers/SUSE.h>

#include "GitHelpers.h"

using namespace SGM;
using Clr = SlHelpers::Color;

void GitHelpers::searchCommit(const SlGit::Repo &repo, const std::set<std::string> &shas,
			      bool skip_signoffs, bool trace,
			      const SearchCallback &pp)
{
	for (const std::string &s: shas) {
		auto commit = repo.commitRevparseSingle(s);
		if (!commit || commit->parentCount() != 1)
			continue;

		auto sha = commit->idStr();

		if (!skip_signoffs) {
			const auto sb = getSomebodyElse(*commit);
			if (!sb.empty()) {
				if (trace)
					std::cerr << "SHA " << sha <<
						     " contains directly our people: skipping maintainers file (suppress this with -M)!\n";
				pp(std::move(sha), sb, {});
				continue;
			}
		}

		auto parent = commit->parent();
		if (!parent) {
			Clr(std::cerr, Clr::RED) << "cannot find commit's parent: " <<
						    git_error_last()->message;
			continue;
		}

		std::set<std::filesystem::path> paths;

		const auto diff = repo.diff(*commit, *parent);
		SlGit::Diff::ForEachCB cb {
			.file = [&paths](const git_diff_delta &delta, float) {
				paths.insert(delta.new_file.path);
				return 0;
			},

		};
		if (diff->forEach(cb)) {
			Clr(std::cerr, Clr::RED) << "cannot walk a diff: " <<
						    git_error_last()->message;
			continue;
		}

		pp(std::move(sha), {}, paths);
	}
}

std::vector<Person> GitHelpers::getSomebodyElse(const SlGit::Commit &commit)
{
	std::vector<Person> ret;
	const auto author = commit.author();
	if (SlHelpers::SUSE::isSUSEAddress(author->email))
		ret.push_back(Person(Role::Author, author->name, author->email));

	const std::string message = commit.message();
	std::istringstream stream(message);
	for (std::string line; std::getline(stream, line);) {
		if (auto p = Person::parse(line))
			if (SlHelpers::SUSE::isSUSEAddress(p->email()))
				ret.push_back(std::move(*p));
	}
	return ret;
}
