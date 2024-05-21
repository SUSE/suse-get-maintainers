set -x
VERSION=$(grep Version: suse-add-cves.spec | awk '{print $2}')
NAME=$(grep Name: suse-add-cves.spec | awk '{print $2}')
DIRECTORY="$NAME-$VERSION"

mkdir "$DIRECTORY"
cp "../$NAME.cc" ../../git2.h ../../helpers.h ../../cves.h ../Makefile "$DIRECTORY"
tar cvJf "$DIRECTORY.tar.xz" "$DIRECTORY" && rm -rf "$DIRECTORY"

