# Packaging (AUR)

`aur/` tracks `aurgen.install.yaml` for the `ramcleaner` AUR package. AURGen generates the `PKGBUILD`, `.SRCINFO`, and the pacman install scriptlet from that file on every run; `aur/.gitignore` ignores every other file there. `pkgver` comes from the git tag `v<version>`. The scriptlet text is `package.install_messages` (`post_install` and `pre_remove`), printed verbatim. `package.post_package` appends a bytecode compile so a root run cannot leave `__pycache__` files pacman does not track. `package.check` is `make check`, the package-time suite run by `check()` on every AUR build; keep it free of git, network, root, user home and live system state.

The package is on the AUR as [`ramcleaner`](https://aur.archlinux.org/packages/ramcleaner). `package.source` is `signed-tag`, so the release build clones the signed `v<version>` git tag and makepkg verifies its signature.

## Test build before a release

`aurgen test` dry-runs every mode and writes only under `aur/dry-run/`. `aurgen local` builds and installs a local test package. `aurgen --dry-run aur` writes the release files there; `aurgen --dry-run git` does the same for the `-git` package.

## Release and publish

1. Edit `aur/aurgen.install.yaml` when package metadata or the install messages change. Bump `__version__` in `ramcleaner/__init__.py` to the version the tag will name.
2. In `CHANGELOG.md`, before tagging, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` for the version just bumped and add a fresh `## [Unreleased]` above it. That renamed section is the GitHub release notes.
3. Run `make lint` and `make test`.
4. Commit, sign the tag, and check it: `git tag -s vX.Y.Z -m "Release vX.Y.Z"`, then `git tag -v vX.Y.Z`. Push with `git push origin main --follow-tags`. `aurgen aur` takes `pkgver` from that tag.
5. Generate the release packaging with `aurgen aur`, then test with `aurgen local` or `aurgen test`.
6. Publish with `aurgen aur-deploy`, which copies the `PKGBUILD`, `.SRCINFO`, and the install scriptlet into the AUR clone and pushes.
