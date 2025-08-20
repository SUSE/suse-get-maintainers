set -x
VERSION=$(grep Version: suse-add-cves.spec | awk '{print $2}')
NAME=$(grep Name: suse-add-cves.spec | awk '{print $2}')
DIRECTORY="$NAME-$VERSION"

mkdir "$DIRECTORY"
cp "../$NAME.cc" ../cve2bugzilla.h ../../curl.h ../../git2.h ../../helpers.h ../../cves.h ../Makefile ../suse-add-cves.1 "$DIRECTORY"
gzip "$DIRECTORY/suse-add-cves.1"
tar cvJf "$DIRECTORY.tar.xz" "$DIRECTORY" && rm -rf "$DIRECTORY"

