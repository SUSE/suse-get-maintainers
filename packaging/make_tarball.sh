set -x
VERSION=$(grep Version: suse-get-maintainers.spec | awk '{print $2}')
NAME=$(grep Name: suse-get-maintainers.spec | awk '{print $2}')
DIRECTORY="$NAME-$VERSION"

mkdir -p "$DIRECTORY/src"
cp "../$NAME.cc" ../git2.h ../helpers.h ../curl.h ../cves.h  ../Makefile ../suse-get-maintainers.1 "$DIRECTORY"
gzip "$DIRECTORY/suse-get-maintainers.1"
cp ../src/*.cc ../src/*.h "$DIRECTORY/src"
tar cvJf "$DIRECTORY.tar.xz" "$DIRECTORY" && rm -rf "$DIRECTORY"

