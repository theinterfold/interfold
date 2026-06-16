# Running a Ciphernode

_NOTE: passing an address to a node may not be required in future versions as we may be moving
towards BLS keys_

You can use the cli to setup your node:

```
$ interfold init
Enter WebSocket devnet RPC URL [wss://ethereum-sepolia-rpc.publicnode.com]: wss://ethereum-sepolia-rpc.publicnode.com
✔ Enter your Ethereum address (press Enter to skip) · 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045


Please enter a new password:
Please confirm your password:
Password sucessfully set.
Interfold configuration successfully created!
You can start your node using `interfold start`
```

This will setup an initial configuration:

```
$ cat ~/.config/interfold/config.yaml
---
# Interfold Configuration File
# Ethereum Account Configuration
address: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
chains:
  - name: "devnet"
    rpc_url: "wss://ethereum-sepolia-rpc.publicnode.com"
    contracts:
      interfold:
        address: "0xCe087F31e20E2F76b6544A2E4A74D4557C8fDf77"
        deploy_block: 7073317
      ciphernode_registry:
        address: "0x0952388f6028a9Eda93a5041a3B216Ea331d97Ab"
        deploy_block: 7073318
      bonding_registry:
        address: "0xcBaCE7C360b606bb554345b20884A28e41436934"
        deploy_block: 7073319
```

It will also setup the nodes key_file in the following path:

```
~/.config/interfold/key
```

You can now setup your wallet if you have your node configured for writing to the blockchain:

```
# Example key DO NOT USE
$ interfold wallet set --private-key "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
```

_\*NOTE: do not use the above private key as this is obviously public and all funds will be lost_

## Configuration

Interfold is configured using a configuration file. By default this file is located under
`~/.config/interfold/config.yaml`

Default values for this file might effectively look like:

```
# ~/.config/interfold/config.yaml
key_file: "{config_dir}/key"
db_file: "{data_dir}/db"
config_dir: "~/.config/interfold"
data_dir: "~/.local/share/interfold"
```

> Note if you set `config_dir` it will change the default location for both the config file and the
> `key_file` and if you specify `data_dir` it will change the default location for the `db_file` for
> example: If I run `interfold start --config ./some-config.yaml` where `./some-config.yaml`
> contains:
>
> ```
> # some-config.yaml
> config_dir: "/my/config/dir"
> ```
>
> The `interfold` binary will look for the key_file under: `/my/config/dir/key`

### Setting a relative folder as a config dir

You may set a relative folder for your config and data dirs.

```
# /path/to/config.yaml
config_dir: ./conf
data_dir: ./data
```

Within the above config the `key_file` location will be: `/path/to/conf/key` and the `db_file` will
be `/path/to/data/db`.

## Providing a registration address

_NOTE: this will likely change soon as we move to using BLS signatures for Ciphernode
identification_

Ciphernodes need a registration address to identify themselves within a committee you can specify
this with the `address` field within the configuration:

```
# ~/.config/interfold/config.yaml
address: "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
```

## Setting your encryption password

Your encryption password is required to encrypt sensitive data within the database such as keys and
wallet private keys. You can set this key in two ways:

1. Use the command line
2. Provide a key file

## Provide your password using the commandline

```
> interfold password set

Please enter a new password:
```

Enter your chosen password.

```
Please confirm your password:
```

Enter your password again to confirm it.

```
Password sucessfully set.
```

Assuming default settings you should now be able to find your keyfile under
`~/.config/interfold/key`

## Provide your password using a key file

You can use a keyfile to provide your password by creating a file under `~/.config/interfold/key`
and setting the file permissions to `400`

```
mkdir -p ~/.config/interfold && read -s password && echo -n "$password" > ~/.config/interfold/key && chmod 400 ~/.config/interfold/key
```

You can change the location of your keyfile by using the `key_file` option within your configuration
file:

```
# ~/.config/interfold/config.yaml
key_file: "/path/to/interfold/key"
```
