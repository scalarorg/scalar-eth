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
    cargo run --package scalar-seth node \
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
    # prepare_network
    case $SERVICE in
        blockscout)
            $DIR/blockscout/run.sh start
            ;;
        network)
            kurtosis run github.com/ethpandaops/ethereum-package --args-file $DIR/kurtosis_params.yaml --image-download always  
            # $DIR/generate-jwt.sh
            # docker compose --env-file $DIR/.env.${ENV} -f ${DIR}/reth.yml -f ${DIR}/lighthouse.yml up -d
            ;;  
        all)
            kurtosis run github.com/ethpandaops/ethereum-package --args-file $DIR/kurtosis_params.yaml --image-download always  
            $DIR/blockscout/run.sh start
            ;;    
        *)
            echo "Unknown service $SERVICE. Do nothing."
            ;;     
    esac         
    
}

stop() {
    case $SERVICE in
        blockscout)
            $DIR/blockscout/run.sh stop
            ;;
        network)
            kurtosis clean -a
            # $DIR/generate-jwt.sh
            # docker compose --env-file $DIR/.env.${ENV} -f ${DIR}/reth.yml -f ${DIR}/lighthouse.yml up -d
            ;;  
        all)
            $DIR/blockscout/run.sh stop
            kurtosis clean -a
            ;;    
        *)
            echo "Unknown service $SERVICE. Do nothing."
            ;;     
    esac    
    
}

usage() {
    cat << USAGE >&2
Usage:
    $RUN_cmdname [-s service] [-c command] [-e environment]
    -s | --service            reth, lighthouse
    -c | --cmd                start, stop, clean, build, clone, update
    -e | --env                environment: local, devnet, testnet, mainnet
USAGE
    exit 1
}
# process arguments
while [[ $# -gt 0 ]]
do
    case "$1" in
        -c | --cmd)
        COMMAND=${2:-start}
        shift 2
        ;;
        -e | --env)
        ENV=${2:-local}
        shift 2
        ;;
        -s | --service)
        SERVICE=${2:-reth}
        shift 2
        ;;
        -h | --help)
        usage
        ;;
        *)
        echoerr "Unknown argument: $1"
        usage
        ;;
    esac
done

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
    stop)
        stop
        ;;  
    *)
        echo "Unknown command: $COMMAND"
        usage
        ;;
esac

