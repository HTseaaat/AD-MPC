function ethermintd() {
    docker run --rm -it \
        -v "$PWD":/external \
        --workdir /external \
        --network host \
        sdumoe-chain-ethermint ethermintd "$@"
}

function command_exists() {
    command -v -- "$1" &>/dev/null
}

function ensure_bash() {
    if [ ! -x /bin/bash ]; then
        echo /bin/bash not found or not executable. 1>&2
        exit 1
    fi
}

function ensure_commands_exists() {
    if [ $# -eq 0 ]; then
        return
    fi

    if command_exists "$1"; then
        shift
        ensure_commands_exists "$@"
    else
        echo Command "$1" is missing. 1>&2
        exit 1
    fi
}

function ensure_root() {
    if [ "$(id -u)" != "0" ]; then
        echo "This script must be run as root" 1>&2
        exit 1
    fi
}

function get_script_dir() {
    (cd "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
}

function ensure_script_dir() {
    (
        script_dir="$(get_script_dir)"
        working_dir="$(pwd)"
        if [ "$script_dir" != "$working_dir" ]; then
            echo Run this script in "$script_dir". 1>&2
            exit 1
        fi
    )
}

function require_positive_integer() {
    if ! [[ $1 =~ ^[0-9]+$ ]]; then
        echo "error: not an integer" >&2
        exit 1
    fi

    if [ "$1" -le 0 ]; then
        echo "error: must be greater than 0" >&2
        exit 1
    fi
}

function rm() {
    echo "rm $@"
    command rm "$@"
}

function ssh() {
    command ssh -o "StrictHostKeyChecking no" -o "UserKnownHostsFile /dev/null" "$@"
}

function scp() {
    command scp -o "StrictHostKeyChecking no" -o "UserKnownHostsFile /dev/null" "$@"
}
