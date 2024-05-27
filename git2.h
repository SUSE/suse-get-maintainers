#ifndef SGM_GIT2_H
#define SGM_GIT2_H

#include <string>
#include <vector>
#include <set>
#include <cstdio>
#include <unordered_map>
#include <sstream>
#include <iostream>
#include <git2.h>

#include "helpers.h"

namespace {
	void validate_shas(std::set<std::string> &s, std::size_t min)
	{
		for (auto &str: s)
			if (!is_hex(str) || (str.size() > 40 || str.size() < min))
				emit_message(str, " does not seem to be a SHA hash of at least ", min, " characters long");
	}

	struct LibGit2
	{
		LibGit2() { git_libgit2_init(); }
		~LibGit2() { git_libgit2_shutdown(); }
	};


	int progress_cb(const char *str, int len, void *)
	{
		std::fprintf(stderr, "\33[2K\rremote: %.*s", len, str);
		return 0;
	}

	void co_progress_cb(const char *path, size_t completed_steps, size_t total_steps, void *)
	{
		std::fprintf(stderr, "\33[2K\rChecked-out: %zu/%zu (%s)%s", completed_steps, total_steps, path, completed_steps == total_steps ? "\n" : "");
	}

	int transfer_progress_cb(const git_indexer_progress *stats, void *)
	{
		if (stats->received_objects == stats->total_objects)
			std::fprintf(stderr, "\33[2K\rResolving deltas %u/%u", stats->indexed_deltas, stats->total_deltas);
		else if (stats->total_objects > 0)
			std::fprintf(stderr, "\33[2K\rReceived %u/%u objects (%u) in %zu bytes",
			       stats->received_objects, stats->total_objects, stats->indexed_objects, stats->received_bytes);
		return 0;
	}

	struct Repo
	{
		Repo() : m_repo(nullptr) {}
		~Repo() { git_repository_free(m_repo); }

		int from_path(const std::string &repo_path) { return git_repository_open(&m_repo, repo_path.c_str()); }
		int clone(const std::string &repo_path, const std::string& url)
			{
				git_checkout_options checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
				checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE;
				checkout_opts.progress_cb = &co_progress_cb;
				git_clone_options clone_opts = GIT_CLONE_OPTIONS_INIT;
				clone_opts.checkout_opts = checkout_opts;
				clone_opts.fetch_opts.callbacks.sideband_progress = &progress_cb;
				clone_opts.fetch_opts.callbacks.transfer_progress = &transfer_progress_cb;
				return git_clone(&m_repo, url.c_str(), repo_path.c_str(), &clone_opts);
			}
		git_repository *get() const { return m_repo; }
	private:
		git_repository *m_repo;
	};

	int update_cb(const char *refname, const git_oid *a, const git_oid *b, void *)
	{
		char a_str[41], b_str[41];
		git_oid_fmt(b_str, b);
		b_str[40] = '\0';

		if (git_oid_is_zero(a))
			std::fprintf(stderr, "[new]     %.20s %s\n", b_str, refname);
		else {
			git_oid_fmt(a_str, a);
			a_str[40] = '\0';
			std::fprintf(stderr, "[updated] %.10s..%.10s %s\n", a_str, b_str, refname);
		}
		return 0;
	}

	struct Remote
	{
		Remote() : m_remote(nullptr)
			{
				m_fetch_opts = GIT_FETCH_OPTIONS_INIT;
				m_fetch_opts.callbacks.update_tips = &update_cb;
				m_fetch_opts.callbacks.sideband_progress = &progress_cb;
				m_fetch_opts.callbacks.transfer_progress = &transfer_progress_cb;
			}
		~Remote() { git_remote_free(m_remote); }
		int from_name(Repo &repo, const std::string &name) { return git_remote_lookup(&m_remote, repo.get(), name.c_str()); }
		int fetch() { return git_remote_fetch(m_remote, nullptr, &m_fetch_opts, "fetch"); }
		void print_stats()
			{
				const git_indexer_progress *stats = git_remote_stats(m_remote);
				if (stats->local_objects > 0)
					std::fprintf(stderr, "Received %u/%u objects in %zu bytes (used %u local objects)\n",
					       stats->indexed_objects, stats->total_objects, stats->received_bytes, stats->local_objects);
				else
					std::fprintf(stderr, "Received %u/%u objects in %zu bytes\n",
					       stats->indexed_objects, stats->total_objects, stats->received_bytes);
			}
		git_remote *get() const { return m_remote; }
	private:
		git_remote *m_remote;
		git_fetch_options m_fetch_opts;
	};

	struct Object
	{
		Object() : m_object(nullptr) {}
		~Object() { git_object_free(m_object); }
		int from_rev(Repo &repo, const std::string &rev) { return git_revparse_single(&m_object, repo.get(), rev.c_str()); }
		git_object *get() const { return m_object; }
	private:
		git_object *m_object;
	};

	struct Commit
	{
		Commit() : m_commit(nullptr) {}
		~Commit() { git_commit_free(m_commit); }

		int from_oid(Repo &repo, const git_oid *oid) { return git_commit_lookup(&m_commit, repo.get(), oid); }
		int from_parent(const Commit &c, unsigned int parent_number = 0) { return git_commit_parent(&m_commit, c.get(), parent_number); }
		Person get_somebody_else(const std::set<std::string> &users) const
			{
				Person ret;
				if (m_commit) {
					Person a;
					const git_signature *author;
					author = git_commit_author(m_commit);
					a.name = author->name;
					a.email = author->email;
					a.role = Role::Author;
					if (is_suse_address(users, a.email)) {
						ret = std::move(a);
						return ret;
					}
					const std::string message = git_commit_message(m_commit);
					std::istringstream stream(message);
					for (std::string line; std::getline(stream, line);) {
						Person p;
						if (p.parse(line) && is_suse_address(users, p.email)) {
							ret = std::move(p);
							return ret;
						}
					}
				}
				return ret;
			}
		unsigned int parent_count() const { return git_commit_parentcount(m_commit); }
		git_commit *get() const { return m_commit; }
	private:
		git_commit *m_commit;
	};

	struct Tree
	{
		Tree() : m_tree(nullptr) {}
		~Tree() { git_tree_free(m_tree); }

		int from_commit(const Commit &c) { return git_commit_tree(&m_tree, c.get()); }
		int from_tree_entry(const Repo &repo, const git_tree_entry *e) {return git_tree_lookup(&m_tree, repo.get(), git_tree_entry_id(e)); }
		std::size_t entry_count() const { return git_tree_entrycount(m_tree); }
		git_tree *get() const { return m_tree; }
	private:
		git_tree *m_tree;
	};

	struct walktree_payload_for_file_map {
		const std::regex &m_r;
		std::unordered_map<std::string, git_oid> &m_paths;
		walktree_payload_for_file_map(const std::regex &r, std::unordered_map<std::string, git_oid> &p) : m_r(r), m_paths(p) {}
	};

	int walktree_for_file_map(const char *root, const git_tree_entry *entry, void *payload)
	{
		walktree_payload_for_file_map *pl = static_cast<walktree_payload_for_file_map *>(payload);
		if (git_tree_entry_type(entry) == GIT_OBJ_BLOB) {
			std::string path(root);
			path += git_tree_entry_name(entry);
			if (std::regex_match(path, pl->m_r))
				pl->m_paths.insert(std::make_pair(path, *git_tree_entry_id(entry)));
		}
		return 0;
	}

	struct Files
	{
		int from_tree_filtered(const Tree &tree, const std::regex &r)
			{
				walktree_payload_for_file_map payload{r, m_paths};
				return git_tree_walk(tree.get(), GIT_TREEWALK_PRE, walktree_for_file_map, &payload);
			}
		std::set<std::string> get_paths() const
			{
				std::set<std::string> ret;
				for (const auto& p: m_paths)
					ret.insert(p.first);
				return ret;
			}
		std::unordered_map<std::string, git_oid> m_paths;
	};

	struct TreeEntry
	{
		TreeEntry() : te(nullptr) {}
		~TreeEntry() { git_tree_entry_free(te); }
		git_tree_entry *te;
	};

	struct Blob
	{
		Blob() : m_blob(nullptr) {}
		~Blob() { git_blob_free(m_blob); }
		int from_tree(Tree &tree, const git_oid *id)
			{
				return git_blob_lookup(&m_blob, git_tree_owner(tree.get()), id);
			}
		int from_tree_and_path(Tree &tree, const std::string &s)
			{
				int err;
				TreeEntry te;
				if ((err = git_tree_entry_bypath(&te.te, tree.get(), s.c_str())))
					return err;
				if (GIT_OBJECT_BLOB != git_tree_entry_type(te.te))
					return GIT_ENOTFOUND;
				return git_blob_lookup(&m_blob, git_tree_owner(tree.get()), git_tree_entry_id(te.te));
			}
		std::string get_file() const { return std::string(static_cast<const char *>(git_blob_rawcontent(m_blob))); }
	private:
		git_blob *m_blob;
	};

	struct FilesContents
	{
		int from_tree_and_files(Tree &tree, const Files &files)
			{
				bool errors = false;
				for (const auto &p: files.m_paths) {
					Blob b;
					if (b.from_tree(tree, static_cast<const git_oid *>(&p.second))) {
						emit_message(git_error_last()->message);
						errors = true;
						continue;
					}
					m_contents.insert(std::make_pair(p.first, b.get_file()));
				}
				return m_contents.empty() && errors ? 1 : 0;
			}
		std::unordered_map<std::string, std::string> m_contents;
	};

	void simple_tree_diff(const Repo &repo, const Tree &pt, const Tree &ct, std::set<std::string> &paths, std::string prefix = std::string());

	struct ObjDiff {
		const git_tree_entry *pte;
		const git_tree_entry *cte;

		ObjDiff() : pte(nullptr), cte(nullptr) {}
	};

	struct walktree_payload_for_diff {
		std::string prefix;
		std::set<std::string> &paths;
		walktree_payload_for_diff(const std::string &n, std::set<std::string> &p) : prefix(n), paths(p) {}
	};

	int walktree_for_diff(const char *root, const git_tree_entry *entry, void *payload)
	{
		walktree_payload_for_diff *pl = static_cast<walktree_payload_for_diff *>(payload);
		const std::string path = root;

		pl->paths.insert(pl->prefix + "/" + root + git_tree_entry_name(entry));
		return 0;
	}

	void simple_tree_entry_add(const git_tree_entry *e, const Repo &repo, std::set<std::string> &paths, const std::string &prefix, const std::string &name)
	{
		const auto type = git_tree_entry_type(e);

		if (type == GIT_OBJECT_BLOB)
			paths.insert(prefix + name);
		else if (type == GIT_OBJECT_TREE) {
			Tree sub;

			if (sub.from_tree_entry(repo, e)) {
				std::cerr << git_error_last()->message << std::endl;
				return;
			}

			walktree_payload_for_diff pl(prefix + name, paths);
			if (git_tree_walk(sub.get(), GIT_TREEWALK_PRE, walktree_for_diff, &pl)) {
				std::cerr << git_error_last()->message << std::endl;
				return;
			}
		}
	}

	void simple_tree_entry_diff(std::string name, const Repo &repo, const git_tree_entry *a, const git_tree_entry *b, std::set<std::string> &paths, const std::string &prefix)
	{
		if (git_oid_cmp(git_tree_entry_id(a), git_tree_entry_id(b)) == 0)
			return;

		const auto type_a = git_tree_entry_type(a);
		const auto type_b = git_tree_entry_type(b);

		if (type_a != type_b) {
			simple_tree_entry_add(a, repo, paths, prefix, name);
			simple_tree_entry_add(b, repo, paths, prefix, name);
		} else if (type_a == GIT_OBJECT_BLOB) {
			simple_tree_entry_add(a, repo, paths, prefix, name);
		} else if (type_a == GIT_OBJECT_TREE) {
			Tree sub_a, sub_b;

			if (sub_a.from_tree_entry(repo, a)) {
				std::cerr << git_error_last()->message << std::endl;
				return;
			}

			if (sub_b.from_tree_entry(repo, b)) {
				std::cerr << git_error_last()->message << std::endl;
				return;
			}

			const std::string new_prefix = prefix + name + "/";
			simple_tree_diff(repo, sub_a, sub_b, paths, new_prefix);
		}
	}

	void simple_tree_diff(const Repo &repo, const Tree &pt, const Tree &ct, std::set<std::string> &paths, std::string prefix)
	{
		std::map<std::string, ObjDiff> entries;
		const auto size_p = pt.entry_count();
		const auto size_c = ct.entry_count();

		for (std::size_t i = 0; i < size_p; ++i) {
			const git_tree_entry *entry = git_tree_entry_byindex(pt.get(), i);
			entries[git_tree_entry_name(entry)].pte = entry;
		}

		for (std::size_t i = 0; i < size_c; ++i) {
			const git_tree_entry *entry = git_tree_entry_byindex(ct.get(), i);
			entries[git_tree_entry_name(entry)].cte = entry;
		}

		for (const auto &[name, diff] : entries) {

			if (diff.pte != nullptr && diff.cte != nullptr)
				simple_tree_entry_diff(name, repo, diff.pte, diff.cte, paths, prefix);
			else if (diff.pte != nullptr)
				simple_tree_entry_add(diff.pte, repo, paths, prefix, name);
			else if (diff.cte != nullptr)
				simple_tree_entry_add(diff.cte, repo, paths, prefix, name);
		}
	}

	void search_commit(Repo &repo,
			   const std::set<std::string> &shas,
			   const std::set<std::string> &suse_users,
			   bool skip_signoffs,
			   std::function<void(const std::string &, const Person &, const std::set<std::string> &)> pp)
	{
		for (const std::string &s: shas) {
			Object obj;
			if (obj.from_rev(repo, s.c_str())) {
				emit_message(s, ": ", git_error_last()->message);
				continue;
			}

			Commit commit;
			if (commit.from_oid(repo, git_object_id(obj.get()))) {
				emit_message(s, ": ", git_error_last()->message);
				continue;
			}
			if (commit.parent_count() != 1)
				continue;

			std::set<std::string> paths;
			Person sb;
			if (!skip_signoffs) {
				sb = commit.get_somebody_else(suse_users);
				if (sb.role != Role::Maintainer) {
					pp(s, sb, paths);
					continue;
				}
			}

			Commit parent;
			if (parent.from_parent(commit)) {
				emit_message(git_error_last()->message);
				continue;
			}

			Tree commit_tree;
			if (commit_tree.from_commit(commit)) {
				emit_message(git_error_last()->message);
				continue;
			}

			Tree parent_tree;
			if (parent_tree.from_commit(parent)) {
				emit_message(git_error_last()->message);
				continue;
			}

			simple_tree_diff(repo, parent_tree, commit_tree, paths);

			pp(s, sb, paths);
		}
	}

	void fetch_repo(const std::string &repo_path, const std::string &name)
	{
		emit_message("Trying to fetch... ", name, " in ", repo_path);
		Repo repo;
		if (repo.from_path(repo_path))
			fail_with_message(git_error_last()->message);

		Remote remote;
		if (remote.from_name(repo, name))
			fail_with_message(git_error_last()->message);

		if (remote.fetch())
			fail_with_message(git_error_last()->message);

		remote.print_stats();
	}
}

#endif
