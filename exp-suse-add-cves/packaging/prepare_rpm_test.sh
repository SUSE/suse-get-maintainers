set -x

rm -rf ~/rpmbuild

./make_tarball.sh

mkdir -p ~/rpmbuild/{SOURCES,SPECS}/

mv *.tar.xz ~/rpmbuild/SOURCES

cp suse-add-cves.spec ~/rpmbuild/SPECS
