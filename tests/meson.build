# SPDX-License-Identifier: GPL-2.0-only

test_curl = executable('test_curl', [
    'test_curl.cpp',
  ],
  implicit_include_directories: false,
  include_directories: [ '..' ],
  dependencies: deps,
  install: true,
)

test('curl unit tests', test_curl)

