#include <cassert>

#include "../Pattern.h"
#include "../Stanza.h"

using namespace SGM;

static void test_pattern()
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
		assert(p->match("drivers/char/ttt/a.c") == 2);
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

static void test_stanza()
{
	Stanza s;

	s.add_pattern("drivers/char/tpm/");
	s.add_pattern("drivers/char/");
	s.add_pattern("drivers/");

	assert(s.match_path("drivers/char/tpm/a.c") == 3);
	assert(s.match_path("drivers/char/ttt/a.c") == 2);
	assert(s.match_path("drivers/ccc/ttt/a.c") == 1);
}

int main()
{
	git_libgit2_init();
	test_pattern();
	test_stanza();
	git_libgit2_shutdown();

	return 0;
}
