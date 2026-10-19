# SPDX-License-Identifier: GPL-3.0-or-later
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib/ramcleaner
# systemd searches $XDG_DATA_HOME/systemd/user for a per-user install, not ~/.local/lib.
USERUNITDIR ?= $(if $(filter $(HOME)/.local,$(patsubst %/,%,$(PREFIX))),$(HOME)/.local/share/systemd/user,$(PREFIX)/lib/systemd/user)
DESTDIR ?=

PY_FILES := $(wildcard ramcleaner/*.py)

.PHONY: install uninstall test lint

install:
	@python3 -c 'import os, sys; exp = os.path.normpath(os.path.join(sys.argv[1], "..", "lib", "ramcleaner")); act = os.path.normpath(sys.argv[2]); sys.exit(0 if act == exp else f"Error: LIBDIR ({act}) must be {exp} relative to BINDIR ({sys.argv[1]})")' "$(BINDIR)" "$(LIBDIR)"
	install -d "$(DESTDIR)$(BINDIR)" "$(DESTDIR)$(LIBDIR)/ramcleaner" "$(DESTDIR)$(USERUNITDIR)"
	install -m 644 $(PY_FILES) "$(DESTDIR)$(LIBDIR)/ramcleaner/"
	install -m 755 bin/ramcleaner "$(DESTDIR)$(BINDIR)/ramcleaner"
	sed "s|@BINDIR@|$(BINDIR)|g" systemd/ramcleaner-watch.service > "$(DESTDIR)$(USERUNITDIR)/ramcleaner-watch.service"
	chmod 644 "$(DESTDIR)$(USERUNITDIR)/ramcleaner-watch.service"
	sed "s|@BINDIR@|$(BINDIR)|g" systemd/ramcleaner-watch.timer > "$(DESTDIR)$(USERUNITDIR)/ramcleaner-watch.timer"
	chmod 644 "$(DESTDIR)$(USERUNITDIR)/ramcleaner-watch.timer"

uninstall:
	rm -f $(patsubst ramcleaner/%,"$(DESTDIR)$(LIBDIR)/ramcleaner/%",$(PY_FILES))
	rm -rf "$(DESTDIR)$(LIBDIR)/ramcleaner/__pycache__"
	rm -f "$(DESTDIR)$(BINDIR)/ramcleaner"
	rm -f "$(DESTDIR)$(USERUNITDIR)/ramcleaner-watch.service" "$(DESTDIR)$(USERUNITDIR)/ramcleaner-watch.timer"
	-rmdir "$(DESTDIR)$(LIBDIR)/ramcleaner" "$(DESTDIR)$(LIBDIR)" 2>/dev/null || true

test:
	python3 -B -m unittest discover -s tests

lint:
	ruff check ramcleaner tests bin/ramcleaner
