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
std::optional<Person> Person::parsePerson(const std::string_view &src, const Role &role)
{
	const auto atSign = src.find_last_of("@");
	if (atSign == std::string::npos)
		return std::nullopt;

	auto personStart = src.find_first_of(":");
	if (personStart == std::string::npos)
		return std::nullopt;
	++personStart;

	const auto emailStart = src.find_first_of("<", personStart);
	if (emailStart == std::string::npos) {
		// 2nd form: no name, only e-mail

		if (src.find_first_of(">", personStart) != std::string::npos)
			return std::nullopt;

		const auto email = SlHelpers::String::trim(src.substr(personStart));
		if (email.find_first_of(" \n\t\r") != std::string::npos)
			return std::nullopt;

		return Person(role, "", std::string(email));
	}

	// 1st form: name <email>

	if (emailStart > atSign)
		return std::nullopt;

	const auto name = SlHelpers::String::trim(src.substr(personStart,
							     emailStart - personStart));
	if (name.empty())
		return std::nullopt;

	const auto emailEnd = src.find_first_of(">", emailStart);
	if (emailEnd == std::string::npos || emailEnd < atSign)
		return std::nullopt;

	const auto email = src.substr(emailStart + 1, emailEnd - emailStart - 1);
	if (email.empty())
		return std::nullopt;

	return Person(role, std::string(name), std::string(email));
}
