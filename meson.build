project('suse-get-maintainers', 'cpp',
  version: '1',
  meson_version: '>= 1.1',
  default_options: [
    'optimization=3',
    'warning_level=2',
    'b_lto=true',
    'b_pie=true',
    'cpp_std=c++20',
  ])

add_project_arguments('-DSUSE_GET_MAINTAINERS_VERSION="' + get_option('SGM_VERSION') + '"', language: 'cpp')
add_project_arguments('-Wno-unused-function', language: 'cpp')
add_project_arguments('-Wno-dangling-else', language: 'cpp')

if host_machine.cpu_family() == 'x86_64'
  add_project_arguments('-march=x86-64-v2', language: 'cpp')
endif

cxxopts = dependency('cxxopts')
json = dependency('nlohmann_json')
libcurl = dependency('slcurl++')
libcves = dependency('slcves++')
libgit2 = dependency('slgit++')
sqlite3 = dependency('slsqlite++')

sgm_lib = static_library('sgm_library', [
    'Pattern.cpp',
    'Person.cpp',
])

prj_name = meson.project_name()
executable(prj_name,
  [
    prj_name + '.cc',
    'GitHelpers.cpp',
    'Maintainers.cpp',
  ],
  link_with: sgm_lib,
  dependencies: [ cxxopts, json, libcves, libcurl, libgit2, sqlite3 ],
  install: true,
)

install_man(prj_name + '.1')

subdir('tests')
