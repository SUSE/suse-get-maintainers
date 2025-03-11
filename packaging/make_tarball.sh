set -x
VERSION=$(grep Version: suse-get-maintainers.spec | awk '{print $2}')
NAME=$(grep Name: suse-get-maintainers.spec | awk '{print $2}')
DIRECTORY="$NAME-$VERSION"

mkdir "$DIRECTORY"
cp "../$NAME.cc" ../maintainers.h ../git2.h ../helpers.h ../curl.h ../cves.h  ../Makefile ../suse-get-maintainers.1 "$DIRECTORY"
# TODO
mkdir "$DIRECTORY/exp-suse-add-cves/"
cp ../exp-suse-add-cves/cve2bugzilla.h "$DIRECTORY/exp-suse-add-cves/"
cp ../temporary.h "$DIRECTORY"
# END TODO
gzip "$DIRECTORY/suse-get-maintainers.1"
tar cvJf "$DIRECTORY.tar.xz" "$DIRECTORY" && rm -rf "$DIRECTORY"

