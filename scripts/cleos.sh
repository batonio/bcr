#!/bin/bash

WORKSPACE_DIR="workspace"
CONTRIB_DIR="$HOME/$WORKSPACE_DIR/bcr/contrib"
PASSWORDS_FILE="$CONTRIB_DIR/account_owner_and_active.keys"
DEFAULT_WALLET_PWD=`cat $CONTRIB_DIR/default_wallet.password`
ACCOUNT_OWNER_PUBLIC_KEY=`cat $PASSWORDS_FILE | grep Owner -A2 | grep Public | awk '{print $3}'`
ACCOUNT_OWNER_PRIVATE_KEY=`cat $PASSWORDS_FILE | grep Owner -A2 | grep Private | awk '{print $3}'`
ACCOUNT_ACTIVE_PUBLIC_KEY=`cat $PASSWORDS_FILE | grep Active -A2 | grep Public | awk '{print $3}'`
ACCOUNT_ACTIVE_PRIVATE_KEY=`cat $PASSWORDS_FILE | grep Active -A2 | grep Private | awk '{print $3}'`
echo "Owner:  $ACCOUNT_OWNER_PRIVATE_KEY $ACCOUNT_OWNER_PUBLIC_KEY"
echo "Active: $ACCOUNT_ACTIVE_PRIVATE_KEY $ACCOUNT_ACTIVE_PUBLIC_KEY"

echo "---"
unlock()
{
export pwd="$1"
expect <(cat <<'EOD'
#set timeout 1

# Debug switcher
#exp_internal 1

set pwd $::env(pwd)
spawn cleos wallet unlock
expect "password:"
send "$pwd\n"
interact
EOD
)
}

lock()
{
    cleos wallet lock
}

keys()
{
    cleos wallet list
    cleos wallet keys
}

create()
{
    cleos create account -j eosio $1 $ACCOUNT_OWNER_PUBLIC_KEY $ACCOUNT_ACTIVE_PUBLIC_KEY
}

get()
{
    cleos get account $1
    cleos get code $1
}

servants()
{
    if [ -n "$1" ]
    then
        cleos get servants $1
    else
        cleos get servants eosio
    fi
}

set()
{
    cleos set contract $1 $2
}

case "$1" in
    unlock)
        echo "Wallet password: $DEFAULT_WALLET_PWD"
        unlock $DEFAULT_WALLET_PWD
    ;;
    keys)
        keys
    ;;
    lock)
        lock
    ;;
    create)
        create $2
    ;;
    get)
        get $2
    ;;
    servants)
        servants $2
    ;;
    set)
        set $2 $3
    ;;
    *)
    echo "Usage: $0 {unlock|lock|keys}"
    echo "Usage: $0 {create <account name>|get <account name>}"
    echo "Usage: $0 {servants [account name]}"
    echo "Usage: $0 {set <account name> <contract path>}"
    exit 1
esac
