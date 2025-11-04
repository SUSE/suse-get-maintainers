# SPDX-License-Identifier: GPL-2.0-only

tests = {
  'maintainers' : [ libgit2 ],
}

foreach t : tests.keys()
  test(t, executable('test_' + t, 'test_' + t + '.cpp',
    link_with: sgm_lib,
    dependencies: tests[t],
    implicit_include_directories: false,
  ))
endforeach
