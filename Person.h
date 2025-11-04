#ifndef SGM_PERSON_H
#define SGM_PERSON_H

#include <optional>
#include <string>

namespace SGM {

class Role {
private:
	static constexpr const std::string roleNames[] = {
		"Author",
		"Signed-off-by",
		"Co-developed-by",
		"Suggested-by",
		"Reviewed-by",
		"Acked-by",
		"Tested-by",
		"Reported-by",
		"Maintainer",
		"Upstream"
	};
public:
	enum RoleType {
		Author,
		SignedOffBy, FirstRole = SignedOffBy,
		CoDevelopedBy,
		SuggestedBy,
		ReviewedBy,
		AckedBy,
		TestedBy, LastRole = TestedBy,
		ReportedBy,
		Maintainer,
		Upstream
	};

	Role() = delete;
	Role(size_t index) : m_role(static_cast<RoleType>(index)) {}
	Role(const RoleType &role) : m_role(role) {}

	RoleType role() const { return m_role; }

	constexpr std::size_t index() const { return static_cast<std::size_t>(m_role); }
	constexpr std::string toString() const { return roleNames[index()]; }
private:
	RoleType m_role;
};

class Person {
public:
	Person() = delete;
	Person(const Role &r, const std::string &name, const std::string &email,
	       unsigned count = 0) :
		m_role(r), m_name(name), m_email(email), m_count(count) {}

	Role role() const { return m_role; }
	const std::string name() const { return m_name; }
	const std::string email() const { return m_email; }
	int count() const { return m_count; }

	std::string pretty(bool includeName = true) const {
		if (includeName && !name().empty())
			return name() + " <" + email() + ">";
		return email();
	}
	template <typename T>
	std::string pretty(const T &translate, bool includeName = true) const {
		if (includeName && !name().empty())
			return name() + " <" + translate(email()) + ">";
		return email();
	}

	void setEmail(const std::string &email) { m_email = email; }

	static std::optional<Person> parsePerson(const std::string_view &src, const Role &role);
	static std::optional<Person> parse(const std::string &src)
	{
		for (std::size_t i = Role::FirstRole; i < Role::LastRole; ++i) {
			Role r(i);
			if (src.starts_with(r.toString()))
				if (auto p = parsePerson(src, r))
					return p;
		}
		return std::nullopt;
	}
private:
	Role m_role;
	std::string m_name;
	std::string m_email;
	unsigned m_count;

};

} // namespace

#endif
