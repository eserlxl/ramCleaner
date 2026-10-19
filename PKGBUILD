# Maintainer: Eser KUBALI <eserlxl@gmail.com>
pkgname=ramcleaner
pkgver=0.1.0
pkgrel=1
pkgdesc="Find processes holding unused memory, attribute them to their owner, and stop them only after approval"
arch=('any')
url="https://github.com/eserlxl/ramCleaner"
license=('GPL-3.0-or-later')
depends=('python>=3.11')
optdepends=('libnotify: Stop/Ignore desktop notifications for ramcleaner watch')
install=ramcleaner.install
source=("$pkgname-$pkgver.tar.gz::$url/archive/refs/tags/v$pkgver.tar.gz")
# Pinned sha256 of the v$pkgver release tarball. The tarball holds this file,
# so after each version bump run `updpkgsums` once the tag is pushed and commit
# the pin separately; never publish with 'SKIP' (see docs/packaging.md).
sha256sums=('SKIP')

check() {
  cd "$srcdir/ramCleaner-$pkgver"
  make test
}

package() {
  cd "$srcdir/ramCleaner-$pkgver"
  make install DESTDIR="$pkgdir" PREFIX=/usr
  # Ship bytecode so a root run cannot leave __pycache__ files pacman does not track.
  python -m compileall -q -o 0 -o 1 -d /usr/lib/ramcleaner "$pkgdir/usr/lib/ramcleaner"
}
