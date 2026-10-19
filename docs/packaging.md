# Packaging (AUR)

The repository ships an Arch `PKGBUILD`, its `.SRCINFO`, and `ramcleaner.install` for the `ramcleaner` AUR package. `package()` delegates to `make install DESTDIR="$pkgdir" PREFIX=/usr`, then precompiles the Python bytecode so a root run cannot leave `__pycache__` files pacman does not track. `check()` runs `make test`.

The package is **not published yet**. Its `source` points at the `v$pkgver` tag tarball on GitHub (`$url/archive/refs/tags/v$pkgver.tar.gz`), so nothing below can succeed until the repository is public there and the tag is pushed.

## Test build before a release

Build from a local archive standing in for the tag tarball; this runs `check()` and installs nothing:

```sh
mkdir -p /tmp/rc-build
git archive --prefix=ramCleaner-0.1.0/ -o /tmp/rc-build/ramcleaner-0.1.0.tar.gz HEAD
cp PKGBUILD ramcleaner.install /tmp/rc-build/
(cd /tmp/rc-build && makepkg -f)
```

## Release and publish

1. Bump `__version__` in `ramcleaner/__init__.py` and `pkgver` in `PKGBUILD` together (reset `pkgrel` to `1`); `tests/test_install.py` fails while they differ.
2. Run `make lint` and `make test`.
3. Commit, tag and push: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`, then `git push origin main --follow-tags`.
4. Pin the checksum once the tag exists: `updpkgsums`, then `makepkg --printsrcinfo > .SRCINFO`, and commit both. The tarball holds the `PKGBUILD`, so the pin is always a separate commit after the tag. Never publish with `sha256sums=('SKIP')`.
5. Build from the real source (`makepkg -f` in a clean directory holding only `PKGBUILD` and `ramcleaner.install`).
6. Push `PKGBUILD`, `.SRCINFO` and `ramcleaner.install` to `ssh://aur@aur.archlinux.org/ramcleaner.git`.
