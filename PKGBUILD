# Maintainer: Eser KUBALI <eserlxl@gmail.com>
pkgname=ramcleaner
pkgver=0.1.0
pkgrel=1
pkgdesc="Find processes holding unused memory, attribute them to their owner, and stop them only after approval"
arch=('any')
url="https://github.com/eserlxl/ramCleaner"
license=('GPL-3.0-or-later')
depends=('python>=3.11')
makedepends=('git')
optdepends=('libnotify: Stop/Later/Hide desktop notifications for ramcleaner watch'
            'zenity: Hide duration menu for ramcleaner watch')
install=ramcleaner.install
source=("$pkgname::git+$url.git#tag=v$pkgver?signed")
# SKIP is correct for a git source: integrity comes from the tag signature
# checked against validpgpkeys, not from a tarball checksum.
sha256sums=('SKIP')
validpgpkeys=('2B0541BF62E91D538C55739DF677BC1E3BD7246E')

check() {
  cd "$srcdir/$pkgname"
  make test
}

package() {
  cd "$srcdir/$pkgname"
  make install DESTDIR="$pkgdir" PREFIX=/usr
  # Ship bytecode so a root run cannot leave __pycache__ files pacman does not track.
  python -m compileall -q -o 0 -o 1 -d /usr/lib/ramcleaner "$pkgdir/usr/lib/ramcleaner"
}
