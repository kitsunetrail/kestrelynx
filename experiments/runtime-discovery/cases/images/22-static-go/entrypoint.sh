#!/bin/sh
# Waits for the signal and then replaces itself with the server.
#
# Replacing rather than starting a child keeps the process the same one:
# the execution the server records is the execution the observation should
# have seen, and there is no second process to confuse the two.
#
# The wait is a blocking read on a pipe, which runs nothing while it waits.
# A polling loop would run an external command on every turn, and every one
# of those is an execution this case is counting.
set -u
FIRE_DIR=${FIRE_DIR:-/run/fire}
if [ -p "$FIRE_DIR/fire" ]; then
	read -r _ <"$FIRE_DIR/fire"
fi
exec /server
