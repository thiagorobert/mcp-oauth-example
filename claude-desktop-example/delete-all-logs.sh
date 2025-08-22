#!/bin/sh

set -e

echo "Deleting ~/claude-desktop-launcher.log"
rm -f ~/claude-desktop-launcher.log
for LOG_FILE in `ls ~/.config/Claude/logs/*.log`; do
    echo "Deleting ${LOG_FILE}"
    rm ${LOG_FILE}
done
for LOG_FILE in `ls /tmp/*.log`; do
    echo "Deleting ${LOG_FILE}"
    rm ${LOG_FILE}
done
