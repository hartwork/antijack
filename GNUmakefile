# Copyright (c) 2023 Sebastian Pipping <sebastian@pipping.org>
# SPDX-License-Identifier: Apache-2.0

CFLAGS += -std=c99 -Wall -Wextra -pedantic -Wno-missing-field-initializers `pkg-config --cflags libseccomp`
LDLIBS += `pkg-config --libs libseccomp`

.PHONY: all
all: antijack

.PHONY: clean
clean:
	$(RM) antijack
