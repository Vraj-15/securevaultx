#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install)
    echo -e "\nsecurevaultx VERSION:"
    securevaultx --version
    echo -e "\nsecurevaultx CONF:"
    cat /etc/securevaultx.conf
    echo -e "\nsecurevaultx SERVICE STATUS BEFORE ENABLE:"
    systemctl status securevaultx || true
    echo -e "\nENABLE securevaultx SERVICE:"
    systemctl enable securevaultx
    echo -e "\nsecurevaultx SERVICE STATUS AFTER ENABLE:"
    systemctl status securevaultx || true
    echo -e "\nSTART securevaultx SERVICE:"
    systemctl start securevaultx
    
    echo -e "\nsecurevaultx SERVICE STATUS AFTER START:"
    sleep 1s
    systemctl status securevaultx
    ;;

  post-upgrade)
    echo -e "\nsecurevaultx VERSION:"
    securevaultx --version

    echo -e "\nsecurevaultx CONF:"
    cat /etc/securevaultx.conf

    echo -e "\nsecurevaultx SERVICE STATUS:"
    systemctl status securevaultx || true
    ;;
esac