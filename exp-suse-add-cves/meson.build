project('suse-add-cves', 'cpp',
  version: '1',
  default_options: [
    'optimization=3',
    'warning_level=2',
    'b_lto=true',
    'b_pie=true',
    'cpp_std=c++20',
  ])

add_project_arguments('-Wno-unused-function', language: 'cpp')
add_project_arguments('-Wno-dangling-else', language: 'cpp')

if host_machine.cpu_family() == 'x86_64'
  add_project_arguments('-march=x86-64-v2', language: 'cpp')
endif

libcurl = dependency('slcurl++')
libgit = dependency('libgit2')

prj_name = meson.project_name()
executable(prj_name,
  [ prj_name + '.cc' ],
  implicit_include_directories: false,
  dependencies: [ libcurl, libgit ],
  install: true,
)

install_man(prj_name + '.1')
