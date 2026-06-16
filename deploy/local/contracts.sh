# !/bin/bash

# Install the interfold binary
# cargo install --locked --path ./crates/cli --bin interfold -f

# Deploy CRISP Contracts
(cd examples/CRISP/packages/crisp-contracts && pnpm deploy:contracts:full:mock --network localhost)

# Add Ciphernodes to Interfold
sleep 2 # wait for interfold to start

# Get the addresses of the ciphernodes
CN1=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
CN2=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
CN3=0x90F79bf6EB2c4f870365E785982E1f101E93b906
CN4=0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65
CN5=0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc

# Add the ciphernodes to the interfold
(cd examples/CRISP/packages/crisp-contracts && pnpm ciphernode:add --ciphernode-address "$CN1" --network "localhost")
(cd examples/CRISP/packages/crisp-contracts && pnpm ciphernode:add --ciphernode-address "$CN2" --network "localhost")
(cd examples/CRISP/packages/crisp-contracts && pnpm ciphernode:add --ciphernode-address "$CN3" --network "localhost")
(cd examples/CRISP/packages/crisp-contracts && pnpm ciphernode:add --ciphernode-address "$CN4" --network "localhost")
(cd examples/CRISP/packages/crisp-contracts && pnpm ciphernode:add --ciphernode-address "$CN5" --network "localhost")


# Delete local DB
(rm -rf ./examples/CRISP/server/database)
