#!/bin/sh

set -e

echo "** ~/claude-desktop-launcher.log"
tail -4 ~/claude-desktop-launcher.log
echo
for LOG_FILE in `ls ~/.config/Claude/logs/*.log`; do
    echo "** ${LOG_FILE}"
    tail -4 ${LOG_FILE}
    echo
done
for LOG_FILE in `ls /tmp/*.log`; do
    echo "** ${LOG_FILE}"
    tail -4 ${LOG_FILE}
    echo
done
