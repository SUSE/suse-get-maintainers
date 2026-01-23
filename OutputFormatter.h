#ifndef SGM_OUTPUTFORMATTER_H
#define SGM_OUTPUTFORMATTER_H

#include <string>
#include <sstream>

#include <nlohmann/json.hpp>

#include <sl/helpers/String.h>
#include <sl/kerncvs/Stanza.h>

namespace SGM {

class OutputFormatter {
public:
	using Person = SlKernCVS::Person;
	using Stanza = SlKernCVS::Stanza;

	OutputFormatter(Stanza::TranslateEmail translateEmail, bool fullNames) :
		m_translateEmail(std::move(translateEmail)), m_fullNames(fullNames) {}

	virtual void newObj() {}
	virtual void add(const std::string &, const std::string &, bool = false) {}
	virtual void addStanza(const Stanza &m) = 0;
	virtual void addPeople(const Stanza::Maintainers &people) = 0;

	virtual void print() const = 0;
protected:
	const Stanza::TranslateEmail m_translateEmail;
	bool m_fullNames;
};

class OutputFormatterJSON : public OutputFormatter {
public:
	using Json = nlohmann::ordered_json;

	OutputFormatterJSON(const Stanza::TranslateEmail &translateEmail,
			    bool fullNames) :
		OutputFormatter(translateEmail, fullNames) {}

	virtual void newObj() override {
		m_json.push_back(Json::object());
	}
	virtual void add(const std::string &key, const std::string &val, bool = false) override {
		m_json.back().push_back({ key, val });
	}
	virtual void addStanza(const Stanza &m) override {
		auto &obj = m_json.back();
		obj.push_back({ "subsystem", m.name() });

		addEmailsAndCounts(m.maintainers());
	}

	virtual void addPeople(const Stanza::Maintainers &sb) override {
		auto &obj = m_json.back();
		obj.push_back({ "roles", nullptr });
		for (const auto &p: sb)
			obj.back().emplace_back(p.role().toString());

		addEmailsAndCounts(sb);
	}

	virtual void print() const override {
		std::cout << std::setw(2) << m_json << '\n';
	}
private:
	void addEmailsAndCounts(const Stanza::Maintainers &sb) {
		unsigned int backport_counts = 0;
		auto &obj = m_json.back();

		obj.push_back({ "emails", nullptr });
		for (const auto &p: sb) {
			backport_counts += p.count();
			obj.back().emplace_back(p.pretty(m_translateEmail, m_fullNames));
		}

		if (backport_counts > 0) {
			obj.push_back({ "counts", nullptr });
			for (const auto &p: sb)
				obj.back().emplace_back(p.count());
		}
	}

	Json m_json;
};

class OutputFormatterCSV : public OutputFormatter {
public:
	OutputFormatterCSV(const Stanza::TranslateEmail &translateEmail, bool fullNames) :
		OutputFormatter(translateEmail, fullNames) {}

	virtual void newObj() override {
		rows.resize(rows.size() + 1);
	}
	virtual void add(const std::string &, const std::string &val,
			 bool quoted = false) override {
		if (quoted)
			rows.back().emplace_back('"' + val + '"');
		else
			rows.back().push_back(val);
	}
	virtual void addStanza(const Stanza &m) override {
		add("name", m.name(), true);

		addEmails(m.maintainers());
	}

	virtual void addPeople(const Stanza::Maintainers &sb) override {
		std::vector<std::string_view> roles;
		for (const Person &p: sb)
			roles.push_back(p.role().toString());
		std::ostringstream ss;
		SlHelpers::String::join(ss, roles, "/");
		add("roles", ss.str(), true);

		addEmails(sb);
	}

	virtual void print() const override {
		for (const auto &row: rows) {
			SlHelpers::String::join(std::cout, row, ",");
			std::cout << '\n';
		}
	}
private:
	void addEmails(const Stanza::Maintainers &sb) {
		auto &row = rows.back();
		for (const auto &p: sb)
			row.push_back(p.pretty(m_translateEmail, m_fullNames));
	}

	std::vector<std::vector<std::string>> rows;
};

class OutputFormatterSimple : public OutputFormatter {
public:
	OutputFormatterSimple(const Stanza::TranslateEmail &translateEmail, bool fullNames) :
		OutputFormatter(translateEmail, fullNames) {}

	virtual void addStanza(const Stanza &m) override {
		for (const auto &p: m.maintainers())
			m_ss << p.pretty(m_fullNames) << '\n';
	}

	virtual void addPeople(const Stanza::Maintainers &sb) override {
		std::set<std::string> duplicate_set;
		for (const Person &p: sb) {
			std::string tmp_email = m_translateEmail(p.email()); // TODO
			if (!duplicate_set.insert(tmp_email).second)
				continue;
			m_ss << p.pretty([&tmp_email](const std::string &) -> std::string {
				return tmp_email;
			}, m_fullNames) << '\n';
		}
	}

	virtual void print() const override {
		std::cout << m_ss.str();
	}
private:
	std::ostringstream m_ss;
};

}

#endif
