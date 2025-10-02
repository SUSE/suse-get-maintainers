# SPDX-License-Identifier: GPL-2.0-only

tests = {
  'curl' : [ libcurl ],
  'maintainers' : [ libgit2 ],
}

foreach t : tests.keys()
  test(t, executable('test_' + t, 'test_' + t + '.cpp',
    dependencies: tests[t],
    implicit_include_directories: false,
  ))
endforeach
