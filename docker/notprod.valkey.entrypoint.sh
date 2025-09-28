#! /bin/sh

if [[ -e /valkey.conf ]]; then
    cp /valkey.conf /data/conf/valkey.conf -r # god dammit stupid brain thought the config file wouldn't be modified on host
fi
if [[ -n  "$VALKEY_PASSWORD" ]]; then
    echo "requirepass $VALKEY_PASSWORD" >> /data/conf/valkey.conf
fi
if [[ -n  "$VALKEY_PASSWORD_FILE" ]]; then
    echo "requirepass $(cat $VALKEY_PASSWORD_FILE)" >> /data/conf/valkey.conf
fi

exec valkey-server /data/conf/valkey.conf