# ramCleaner

[![License: GPL v3+](https://img.shields.io/badge/License-GPLv3%2B-blue.svg)](LICENSE)

ramCleaner finds processes that hold memory they no longer use (idle helper copies a daemon
forgot to close, zombies nobody reaps, processes that only grow), shows which application really
owns them, and stops them only after you approve. It never stops anything on its own.

Status: under development. See [docs/design.md](docs/design.md).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
