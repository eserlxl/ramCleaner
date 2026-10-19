# Packaging (AUR)

The `aur/` directory holds the Arch `PKGBUILD`, its `.SRCINFO`, and `ramcleaner.install` for the `ramcleaner` AUR package; `aur/.gitignore` keeps everything else there (the git clone, `src/`, `pkg/`, built packages) out of git. `package()` delegates to `make install DESTDIR="$pkgdir" PREFIX=/usr`, then precompiles the Python bytecode so a root run cannot leave `__pycache__` files pacman does not track. `check()` runs `make test`.

The package is **not published yet**. Its `source` is the signed `v$pkgver` git tag (`git+$url.git#tag=v$pkgver?signed`). `sha256sums=('SKIP')` stays: makepkg checks the tag signature against `validpgpkeys` (`2B0541BF62E91D538C55739DF677BC1E3BD7246E`) instead of a tarball checksum, so no checksum commit is needed after the tag. A build from GitHub cannot succeed until the repository is public there and a signed tag is pushed. makepkg refuses an unsigned or wrongly signed tag.

## Test build before a release

Build from this clone with a temporary signed tag; this runs `check()` and installs nothing. The committed `source` points at the GitHub release tag, so the copy used here is pointed at the local clone (`git+file://`) and at the temporary tag, and runs before anything is pushed. The real `vX.Y.Z` tag is only created at release time (step 4 below):

```sh
git tag -s test-build -m "Test build"
mkdir -p /tmp/rc-build
cp aur/PKGBUILD aur/ramcleaner.install /tmp/rc-build/
sed -i "s|git+\$url.git#tag=v\$pkgver|git+file://$(pwd)#tag=test-build|" /tmp/rc-build/PKGBUILD
(cd /tmp/rc-build && makepkg -f)
git tag -d test-build
```

makepkg refuses an unsigned or wrongly signed tag. The public half of the signing key must already be in the keyring (`git tag -v test-build` checks the same signature).

## Release and publish

1. Bump `__version__` in `ramcleaner/__init__.py` and `pkgver` in `aur/PKGBUILD` together (reset `pkgrel` to `1`); `tests/test_install.py` fails while they differ. Regenerate `aur/.SRCINFO` in that same commit with `cd aur && makepkg --printsrcinfo > .SRCINFO`.
2. In `CHANGELOG.md`, before tagging, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` for the version just bumped and add a fresh `## [Unreleased]` above it. That renamed section is the GitHub release notes.
3. Run `make lint` and `make test`.
4. Commit, sign the tag, and check it: `git tag -s vX.Y.Z -m "Release vX.Y.Z"`, then `git tag -v vX.Y.Z`. Push with `git push origin main --follow-tags`.
5. Build from the real source: `cd aur && makepkg -f` (the build output stays ignored by `aur/.gitignore`).
6. Push `aur/PKGBUILD`, `aur/.SRCINFO` and `aur/ramcleaner.install` to `ssh://aur@aur.archlinux.org/ramcleaner.git`.
