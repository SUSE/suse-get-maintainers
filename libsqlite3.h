#ifndef SGM_SQLITE3_H
#define SGM_SQLITE3_H

#include <sqlite3.h>
#include "helpers.h"

namespace {
	struct Database
	{
		Database() : database(nullptr) {}
		~Database() { sqlite3_close(database); }

		Database(const Database&) = delete;
		Database& operator=(const Database&) = delete;

		Database(Database&& o) noexcept : database(o.database) {
			o.database = nullptr;
		}

		Database& operator=(Database&& o) noexcept {
			if (this != &o) {
				sqlite3_close(database);
				database = o.database;
				o.database = nullptr;
			}
			return *this;
		}

		int from_path(const std::string &db_path) { return sqlite3_open(db_path.c_str(), &database); }

		sqlite3 *database;
	};

	constexpr char get_maintainers[] = "SELECT user.email, sum(map.count_no_fixes) AS cnt " \
		"FROM user_file_map AS map " \
		"LEFT JOIN user ON map.user = user.id " \
		"WHERE map.file = (SELECT id FROM file WHERE file = ? " \
		"AND dir = (SELECT id FROM dir WHERE dir = ?)) " \
		"GROUP BY substr(user.email, 0, instr(user.email, '@')) " \
		"ORDER BY cnt DESC, user.email " \
		"LIMIT ?;";

	struct GetMaintainers
	{
		std::string email;
		int count;
	};

	struct Statement
	{
		Statement() : statement(nullptr) {}
		~Statement() { sqlite3_finalize(statement); }

		Statement(const Statement&) = delete;
		Statement& operator=(const Statement&) = delete;

		Statement(Statement&& o) noexcept : statement(o.statement) {
			o.statement = nullptr;
		}

		Statement& operator=(Statement&& o) noexcept {
			if (this != &o) {
				sqlite3_finalize(statement);
				statement = o.statement;
				o.statement = nullptr;
			}
			return *this;
		}

		int prepare(Database &db, const std::string &sql_query) {
			return sqlite3_prepare_v2(db.database, sql_query.c_str(), sql_query.size(), &statement, nullptr);
		}

		int prepare_get_maintainers(Database &db) {
			return prepare(db, get_maintainers);
		}

		void reset() {
			if (!statement)
				return;
			sqlite3_reset(statement);
			sqlite3_clear_bindings(statement);
		}

		int bind_get_maitainers(const std::string &file, const std::string &dir, int limit) {
			reset();

			int err = 0;
			err = sqlite3_bind_text(statement, 1, file.c_str(), file.size(), SQLITE_STATIC);
			if (err)
				return err;
			err = sqlite3_bind_text(statement, 2, dir.c_str(), dir.size(), SQLITE_STATIC);
			if (err)
				return err;
			return sqlite3_bind_int(statement, 3, limit);
		}

		int step_get_maitainers(std::vector<GetMaintainers> &out) {
			int rc = 0;
			for (;;) {
				rc = sqlite3_step(statement);
				if (rc == SQLITE_ROW) {
					std::string email = reinterpret_cast<const char *>(sqlite3_column_text(statement, 0));
					int count = sqlite3_column_int(statement, 1);
					out.emplace_back(std::move(email), count);
				} else if (rc == SQLITE_DONE)
					return 0;
				else
					break;
			}
			return rc;
		}

		sqlite3_stmt *statement;
	};
}
#endif
