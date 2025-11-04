# SPDX-License-Identifier: GPL-2.0-only

tests = {
  'maintainers' : { 'libs': [ libgit2 ], 'sources': [ '../Pattern.cpp', '../Person.cpp' ] },
}

foreach t : tests.keys()
  test(t, executable('test_' + t, [ 'test_' + t + '.cpp', tests[t]['sources'] ],
    dependencies: tests[t]['libs'],
    implicit_include_directories: false,
  ))
endforeach
