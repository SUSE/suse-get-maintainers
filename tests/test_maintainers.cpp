#include <cassert>

#include "../Pattern.h"
#include "../Person.h"
#include "../Stanza.h"

using namespace SGM;

namespace {

void test_pattern()
{
	{
		auto p = Pattern::create("drivers/char/tpm/");
		assert(p);
		assert(!p->match("drivers/char/a.c"));
		assert(p->match("drivers/char/tpm/a.c") == 3);
	}

	{
		const auto p = Pattern::create("drivers/char/");
		assert(p);
		assert(p->match("drivers/char/a.c") == 2);
	}

	{
		const auto p = Pattern::create("drivers/*");
		assert(p);
		assert(!p->match("driver/char/a.c"));
		assert(p->match("drivers/char/ttt/a.c") == 1);
	}

	{
		const auto p = Pattern::create("drivers/*/b.c");
		assert(p);
		assert(!p->match("drivers/char/tpm/a.c"));
		assert(p->match("drivers/char/tpm/b.c") == 3);
	}

	{
		const auto p = Pattern::create("*/b.c");
		assert(p);
		assert(p->match("drivers/char/tpm/b.c") == 2);
		assert(!p->match("drivers/char/tpm/a.c"));
	}

	{
		const auto p = Pattern::create("drivers/char/?.c");
		assert(p);
		assert(p->match("drivers/char/a.c"));
		assert(p->match("drivers/char/b.c"));
		assert(!p->match("drivers/char/b.h"));
	}
}

void test_person()
{
	static const std::string email("email@somewhere.com");
	static const std::string email2("email2@somewhere.com");
	static const std::string name("Some Maintainer");
	static const std::string name2("Some Longer Longer Maintainer");
	{
		const auto p = Person::parsePerson("M: " + email, Role::Maintainer);
		assert(p);
		assert(p->name().empty());
		assert(p->email() == email);
		assert(p->role().role() == Role::Maintainer);
		assert(p->role().toString() == "Maintainer");
	}
	{
		const auto p = Person::parsePerson("M: " + name + " <" + email + '>',
						   Role::Author);
		assert(p);
		assert(p->name() == name);
		assert(p->email() == email);
		assert(p->role().role() == Role::Author);
		assert(p->role().toString() == "Author");
	}
	{
		auto p = Person::parsePerson("M: " + name2 + " <" + email + '>',
						   Role::Author);
		assert(p);
		assert(p->name() == name2);
		assert(p->email() == email);
		p->setEmail(email2);
		assert(p->email() == email2);
		assert(p->pretty() == name2 + " <" + email2 + '>');
		assert(p->pretty([](const auto &e) { return "foo-" + e; }) ==
		       name2 + " <foo-" + email2 + '>');
	}
	assert(!Person::parsePerson("M " + name + " <" + email + '>', Role::Maintainer));
	assert(!Person::parsePerson("M: " + name + " <foo>", Role::Maintainer));
	assert(!Person::parsePerson("M: " + name + " >" + email + '>', Role::Maintainer));
	assert(!Person::parsePerson("M: " + name + " <" + email, Role::Maintainer));
}

void test_stanza()
{
	Stanza s;

	s.add_pattern("drivers/char/tpm/");
	s.add_pattern("drivers/char/");
	s.add_pattern("drivers/");

	assert(s.match_path("drivers/char/tpm/a.c") == 3);
	assert(s.match_path("drivers/char/ttt/a.c") == 2);
	assert(s.match_path("drivers/ccc/ttt/a.c") == 1);
}

} //namespace

int main()
{
	test_pattern();
	test_person();
	test_stanza();

	return 0;
}
