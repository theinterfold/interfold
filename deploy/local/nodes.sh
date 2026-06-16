# !/bin/bash

# Install the interfold binary
# cargo install --locked --path ./crates/cli --bin interfold -f

concurrently \
  --names "ANVIL,NODES" \
  --prefix-colors "blue,yellow" \
  "anvil" \
  "cd examples/CRISP && \
  interfold wallet set --name cn1 --private-key "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" && 
  interfold wallet set --name cn2 --private-key "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" && 
  interfold wallet set --name cn3 --private-key "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6" &&
  interfold wallet set --name cn4 --private-key "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a" &&
  interfold wallet set --name cn5 --private-key "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba" &&
  interfold nodes up -v"