#include <sl/helpers/String.h>

#include "Person.h"

using namespace SGM;

/**
 * @brief Parse \p src into a Person
 * @param src Line to parse
 * @param role Role to set to the new Person
 * @param count Count to set to the new Person
 * @return Person, or nullopt in case of failure
 *
 * Parses lines like:
 * M: First LastName <email@somewhere.com>
 * M: email@somewhere.com
 */
std::optional<Person> Person::parsePerson(const std::string_view &src, const Role &role,
					  unsigned count)
{
	std::string_view name, email;
	auto pos = src.find_last_of("@");
	if (pos == std::string::npos)
		return std::nullopt;
	auto e_sign = src.find_first_of(":");
	if (e_sign == std::string::npos)
		return std::nullopt;
	++e_sign;
	auto b_mail = src.find_first_of("<", e_sign);
	if (b_mail == std::string::npos)
		if (src.find_first_of(">", e_sign) != std::string::npos)
			return std::nullopt;
		else {
			email = SlHelpers::String::trim(src.substr(e_sign));
			if (email.find_first_of(" \n\t\r") != std::string::npos)
				return std::nullopt;
			else {
				return Person(role, "", std::string(email), count);
			}
		}
	if (b_mail > pos)
		return std::nullopt;
	name = SlHelpers::String::trim(src.substr(e_sign, b_mail - e_sign));
	if (name.empty())
		return std::nullopt;
	auto e_mail = src.find_first_of(">", b_mail);
	if (e_mail ==  std::string::npos || e_mail < pos)
		return std::nullopt;
	email = src.substr(b_mail + 1, e_mail - b_mail - 1);
	if (email.empty())
		return std::nullopt;

	return Person(role, std::string(name), std::string(email), count);
}
