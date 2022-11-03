#! /bin/bash
# SPDX-License-Identifier: GPL-2.0

if [ -d "$1" ]; then
    exit 0
fi

exit 1
