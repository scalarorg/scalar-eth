#!/bin/bash
# https://reth.rs/installation/docker.html
DIR="$( cd "$( dirname "$0" )" && pwd )"
RUN_cmdname=${0##*/}

prepare_network() {
    export NETWORK_NAME=${DOCKER_NETWORK:-scalaris-evm-local}
    SUBNET=${DOCKER_SUBNET:-172.16.10.0/24}
    if [ -z $(docker network ls --filter name=^${NETWORK_NAME}$ --format="{{ .Name }}") ] ; then 
        docker network create \
        --driver=bridge \
        --subnet=${SUBNET} \
        ${NETWORK_NAME}
    fi
}

dev() {
    export ENV=${ENV:-local}
    cd $DIR/..
    RUST_LOG=debug
    cargo run --package scalar node \
    --dev \
    --dev.block-time 12s \
    --engine.experimental
   
    # cargo run node 
}
test() {
    cd $DIR/..
    RUST_BACKTRACE=full RUST_LOG=debug cargo test -p scalar-testing --features pevm-tests
}
start() {
    export ENV=${ENV:-local}
    cd $DIR/..
    RUST_LOG=info
    cargo run --package scalar node \
    --dev \
    --dev.block-time 12s \
    --engine.experimental   
    
}

# process arguments
COMMAND=${1:-start}

case $COMMAND in
    dev)
        dev
        ;;
    test)
        test
        ;;
    start)
        start
        ;;
    *)
        echo "Unknown command: $COMMAND"
        usage
        ;;
esac

