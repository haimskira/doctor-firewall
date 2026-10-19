#!/bin/sh
# Start Redis with the password from the Docker secret written into a private
# tmpfs config file (never on the command line). Dangerous admin commands are off.
set -eu
umask 077
{
    printf 'requirepass %s\n' "$(cat /run/secrets/redis_password)"
    echo 'appendonly yes'
    echo 'dir /data'
    echo 'protected-mode yes'
    echo 'rename-command FLUSHALL ""'
    echo 'rename-command CONFIG ""'
    echo 'rename-command DEBUG ""'
    echo 'rename-command SHUTDOWN ""'
    echo 'rename-command MODULE ""'
} > /tmp/redis.conf
exec redis-server /tmp/redis.conf
