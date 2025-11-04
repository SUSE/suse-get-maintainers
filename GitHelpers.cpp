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

		if (!skip_signoffs) {
			const auto sb = getSomebodyElse(*commit);
			if (!sb.empty()) {
				if (trace)
					std::cerr << "SHA " << s <<
						     " contains directly our people: skipping maintainers file (suppress this with -M)!\n";
				pp(s, sb, {});
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

		simpleTreeDiff(repo, *parent->tree(), *commit->tree(), paths);

		pp(s, {}, paths);
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

void GitHelpers::simpleTreeEntryAdd(const SlGit::TreeEntry &e, const SlGit::Repo &repo,
				       std::set<std::filesystem::path> &paths,
				       const std::string &prefix, const std::string &name)
{
	const auto type = e.type();

	if (type == GIT_OBJECT_BLOB)
		paths.insert(prefix + name);
	else if (type == GIT_OBJECT_TREE) {
		auto sub = repo.treeLookup(e);
		if (!sub) {
			Clr(std::cerr, Clr::RED) << git_error_last()->message;
			return;
		}

		if (sub->walk([&paths, &prefix, &name](const std::string &path,
						       const SlGit::TreeEntry &e) -> int {
			      paths.insert(prefix + name + "/" + path + e.name());
			      return 0;
	})) {
			Clr(std::cerr, Clr::RED) << git_error_last()->message;
			return;
		}
	}
}

void GitHelpers::simpleTreeEntryDiff(const std::string &name, const SlGit::Repo &repo,
				     const SlGit::TreeEntry &a, const SlGit::TreeEntry &b,
				     std::set<std::filesystem::path> &paths,
				     const std::string &prefix)
{
	if (git_oid_cmp(a.id(), b.id()) == 0)
		return;

	const auto type_a = a.type();
	const auto type_b = b.type();

	if (type_a != type_b) {
		simpleTreeEntryAdd(a, repo, paths, prefix, name);
		simpleTreeEntryAdd(b, repo, paths, prefix, name);
	} else if (type_a == GIT_OBJECT_BLOB) {
		simpleTreeEntryAdd(a, repo, paths, prefix, name);
	} else if (type_a == GIT_OBJECT_TREE) {
		auto sub_a = repo.treeLookup(a);
		if (!sub_a) {
			Clr(std::cerr, Clr::RED) << git_error_last()->message;
			return;
		}

		auto sub_b = repo.treeLookup(b);
		if (!sub_b) {
			Clr(std::cerr, Clr::RED) << git_error_last()->message;
			return;
		}

		const std::string new_prefix = prefix + name + "/";
		simpleTreeDiff(repo, *sub_a, *sub_b, paths, new_prefix);
	}
}

struct ObjDiff {
	std::optional<const SlGit::TreeEntry> pte;
	std::optional<const SlGit::TreeEntry> cte;

	ObjDiff() : pte(std::nullopt), cte(std::nullopt) {}
};

void GitHelpers::simpleTreeDiff(const SlGit::Repo &repo, const SlGit::Tree &pt,
				const SlGit::Tree &ct, std::set<std::filesystem::path> &paths,
				const std::string &prefix)
{
	std::map<std::string, ObjDiff> entries;
	const auto size_p = pt.entryCount();
	const auto size_c = ct.entryCount();

	for (std::size_t i = 0; i < size_p; ++i) {
		auto entry = pt.treeEntryByIndex(i);
		entries[entry.name()].pte.emplace(std::move(entry));
	}

	for (std::size_t i = 0; i < size_c; ++i) {
		auto entry = ct.treeEntryByIndex(i);
		entries[entry.name()].cte.emplace(std::move(entry));
	}

	for (const auto &[name, diff] : entries) {
		if (diff.pte && diff.cte)
			simpleTreeEntryDiff(name, repo, *diff.pte, *diff.cte, paths, prefix);
		else if (diff.pte)
			simpleTreeEntryAdd(*diff.pte, repo, paths, prefix, name);
		else if (diff.cte)
			simpleTreeEntryAdd(*diff.cte, repo, paths, prefix, name);
	}
}
