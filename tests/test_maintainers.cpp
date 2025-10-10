#include <cassert>

#include "../maintainers.h"

static void test_pattern()
{
	{
		Pattern p{"drivers/char/tpm/"};
		assert(!p.match("drivers/char/a.c"));
		assert(p.match("drivers/char/tpm/a.c") == 3);
	}

	{
		Pattern p{"drivers/char/"};
		assert(p.match("drivers/char/a.c") == 2);
	}

	{
		Pattern p{"drivers/*"};
		assert(!p.match("driver/char/a.c"));
		assert(p.match("drivers/char/ttt/a.c") == 2);
	}

	{
		Pattern p{"drivers/*/b.c"};
		assert(!p.match("drivers/char/tpm/a.c"));
		assert(p.match("drivers/char/tpm/b.c") == 3);
	}

	{
		Pattern p{"*/b.c"};
		assert(p.match("drivers/char/tpm/b.c") == 2);
		assert(!p.match("drivers/char/tpm/a.c"));
	}

	{
		Pattern p{"drivers/char/?.c"};
		assert(p.match("drivers/char/a.c"));
		assert(p.match("drivers/char/b.c"));
		assert(!p.match("drivers/char/b.h"));
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
