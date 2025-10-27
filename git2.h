#ifndef SGM_GIT2_H
#define SGM_GIT2_H

#include <functional>
#include <string>
#include <set>
#include <cstdio>
#include <sstream>
#include <iostream>

#include <sl/git/Git.h>
#include <sl/helpers/Misc.h>
#include <sl/helpers/String.h>

#include "helpers.h"
#include "Person.h"

namespace {
	void validate_shas(std::set<std::string> &s, std::size_t min)
	{
		for (auto &str: s)
			if (!SlHelpers::String::isHex(str) || (str.size() > 40 || str.size() < min))
				std::cerr << str <<
					     " does not seem to be a SHA hash of at least " <<
					     min << " characters long\n";
	}

	std::vector<SGM::Person> get_somebody_else(const SlGit::Commit &commit,
						   const std::set<std::string> &users)
	{
		std::vector<SGM::Person> ret;
		const auto author = commit.author();
		if (is_suse_address(users, author->email))
			ret.push_back(SGM::Person(SGM::Role::Author, author->name, author->email));

		const std::string message = commit.message();
		std::istringstream stream(message);
		for (std::string line; std::getline(stream, line);) {
			if (auto p = SGM::Person::parse(line))
				if (is_suse_address(users, p->email()))
					ret.push_back(std::move(*p));
		}
		return ret;
	}

	void simple_tree_diff(const SlGit::Repo &repo, const SlGit::Tree &pt, const SlGit::Tree &ct,
			      std::set<std::filesystem::path> &paths,
			      const std::string &prefix = std::string());

	struct ObjDiff {
		std::optional<const SlGit::TreeEntry> pte;
		std::optional<const SlGit::TreeEntry> cte;

		ObjDiff() : pte(std::nullopt), cte(std::nullopt) {}
	};

	void simple_tree_entry_add(const SlGit::TreeEntry &e, const SlGit::Repo &repo,
				   std::set<std::filesystem::path> &paths, const std::string &prefix,
				   const std::string &name)
	{
		const auto type = e.type();

		if (type == GIT_OBJECT_BLOB)
			paths.insert(prefix + name);
		else if (type == GIT_OBJECT_TREE) {
			auto sub = repo.treeLookup(e);
			if (!sub) {
				std::cerr << git_error_last()->message << std::endl;
				return;
			}

			if (sub->walk([&paths, &prefix, &name](const std::string &path,
							   const SlGit::TreeEntry &e) -> int {
				paths.insert(prefix + name + "/" + path + e.name());
				return 0;
			})) {
				std::cerr << git_error_last()->message << std::endl;
				return;
			}
		}
	}

	void simple_tree_entry_diff(const std::string &name, const SlGit::Repo &repo,
				    const SlGit::TreeEntry &a, const SlGit::TreeEntry &b,
				    std::set<std::filesystem::path> &paths, const std::string &prefix)
	{
		if (git_oid_cmp(a.id(), b.id()) == 0)
			return;

		const auto type_a = a.type();
		const auto type_b = b.type();

		if (type_a != type_b) {
			simple_tree_entry_add(a, repo, paths, prefix, name);
			simple_tree_entry_add(b, repo, paths, prefix, name);
		} else if (type_a == GIT_OBJECT_BLOB) {
			simple_tree_entry_add(a, repo, paths, prefix, name);
		} else if (type_a == GIT_OBJECT_TREE) {
			auto sub_a = repo.treeLookup(a);
			if (!sub_a) {
				std::cerr << git_error_last()->message << std::endl;
				return;
			}

			auto sub_b = repo.treeLookup(b);
			if (!sub_b) {
				std::cerr << git_error_last()->message << std::endl;
				return;
			}

			const std::string new_prefix = prefix + name + "/";
			simple_tree_diff(repo, *sub_a, *sub_b, paths, new_prefix);
		}
	}

	void simple_tree_diff(const SlGit::Repo &repo, const SlGit::Tree &pt,
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
				simple_tree_entry_diff(name, repo, *diff.pte, *diff.cte, paths,
						       prefix);
			else if (diff.pte)
				simple_tree_entry_add(*diff.pte, repo, paths, prefix, name);
			else if (diff.cte)
				simple_tree_entry_add(*diff.cte, repo, paths, prefix, name);
		}
	}

	void search_commit(const SlGit::Repo &repo,
			   const std::set<std::string> &shas,
			   const std::set<std::string> &suse_users,
			   bool skip_signoffs,
			   bool trace,
			   const std::function<void (const std::string &,
						     const std::vector<SGM::Person> &,
						     const std::set<std::filesystem::path> &)> &pp)
	{
		for (const std::string &s: shas) {
			auto commit = repo.commitRevparseSingle(s);
			if (!commit || commit->parentCount() != 1)
				continue;

			std::set<std::filesystem::path> paths;
			std::vector<SGM::Person> sb;
			if (!skip_signoffs) {
				sb = get_somebody_else(*commit, suse_users);
				if (!sb.empty()) {
					if (trace)
						std::cerr << "SHA " << s <<
							     " contains directly our people: skipping maintainers file (suppress this with -M)!\n";
					pp(s, sb, paths);
					continue;
				}
			}

			auto parent = commit->parent();
			if (!parent) {
				std::cerr << "cannot find commit's parent: " <<
					     git_error_last()->message << '\n';
				continue;
			}

			simple_tree_diff(repo, *parent->tree(), *commit->tree(), paths);

			pp(s, sb, paths);
		}
	}
}

#endif
