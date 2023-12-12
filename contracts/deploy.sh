#!/bin/bash

mkdir -p deployments/${NETWORK} 

N=$(echo "$CONTRACTS" | wc -w)
CONTRACTS_SOURCE_FILES=$(ls "/opt/contracts/src/$NETWORK")

if [ ${N} != $(echo "$CONTRACTS_SOURCE_FILES" | wc -w) ]; then
    echo "The number of CONTRACTS and CONTRACTS_SOURCE_FILES must be equal!"
    exit 1
fi

# deploy the contracts
for i in $(seq 1 $N); do
    CONTRACT=$(echo "$CONTRACTS" | cut -d " " -f $i)
    CONTRACT_SOURCE_FILE=$(echo "$CONTRACTS_SOURCE_FILES" | cut -d $'\n' -f $i)
    
    echo "Deploying $CONTRACT from $CONTRACT_SOURCE_FILE on $NETWORK network."
    forge create --rpc-url "$RPC_URL" --mnemonic "$MNEMONIC" --json "/opt/contracts/src/$NETWORK/$CONTRACT_SOURCE_FILE:$CONTRACT" \
    | jq . | tee "deployments/$NETWORK/$CONTRACT.json"
done
