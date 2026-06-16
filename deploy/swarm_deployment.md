# Setup a remote server

Install docker

```
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release
sudo mkdir -m 0755 -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo docker run hello-world
```

Initialize swarm

```
docker swarm init
```

NOTE: If you get an error about not being able to choose between IP addresses choose the more
private IP address.

```
docker swarm init --advertise-addr 10.49.0.5
```

## Setting up Buildkit

NOTE: You may need to setup buildkit:

```
echo '{
  "builder": {
    "gc": {
      "enabled": true,
      "defaultKeepStorage": "20GB"
    }
  },
  "features": {
    "buildkit": true,
    "containerd-snapshotter": true
  }
}' | sudo tee /etc/docker/daemon.json
```

and then restart the docker daemon

```
sudo systemctl restart docker
```

## Setup the repo

Clone the repo

```
git clone https://github.com/gnosisguild/interfold.git
```

Move to the new folder:

```
cd interfold/
```

Build the app

```
./deploy/build.sh
```

# Setup `.env` vars

Copy the `.env.example` file to `.env`

```
cp ./deploy/.env.example ./deploy/.env
```

Alter the variables to reflect the correct values required for the stack:

```
export RPC_URL=wss://eth-sepolia.g.alchemy.com/v2/<SOME_API_KEY>
export SEPOLIA_INTERFOLD_ADDRESS=0xCe087F31e20E2F76b6544A2E4A74D4557C8fDf77
export SEPOLIA_CIPHERNODE_REGISTRY_ADDRESS=0x0952388f6028a9Eda93a5041a3B216Ea331d97Ab
export SEPOLIA_BONDING_REGISTRY=0xcBaCE7C360b606bb554345b20884A28e41436934
```

Pay special attention to the `RPC_URL` vars as here we use a standin API key value.

You can peruse the yaml config files for the nodes to see how the vars are used within the config.

# Secrets Setup Utils Script

We have created a secrets setup utility to aid setting up the secrets for each node.

To deploy with swarm we need to set up the secrets file for our cluster.

## Run

```bash
./deploy/copy-secrets.sh
```

## What it does

- Copies `example.secrets.json` to create `cn1/2/3/4.secrets.json` files
- Skips existing files
- Warns with yellow arrows (==>) if any files are identical to the example

## Example output

```bash
Created cn1.secrets.json
Skipping cn2.secrets.json - file already exists

==> cn1.secrets.json <== # Yellow arrows indicate files that need customization
```

Remember to modify any highlighted files before use with unique secrets.

# Deploy a version to the stack

To deploy

```
./deploy/deploy.sh interfold ghcr.io/gnosisguild/ciphernode:latest
```

This will deploy the following services:

```
❯ docker service ls
ID             NAME                 MODE         REPLICAS   IMAGE                  PORTS
tr44go8vevh1   interfold_cn4          replicated   1/1        ghcr.io/gnosisguild/ciphernode:latest
kdqktv85xcuv   interfold_cn1          replicated   1/1        ghcr.io/gnosisguild/ciphernode:latest
nguul381w6mu   interfold_cn2          replicated   1/1        ghcr.io/gnosisguild/ciphernode:latest
zgmwmv7cd63j   interfold_cn3          replicated   1/1        ghcr.io/gnosisguild/ciphernode:latest
```

# Get the logs

You can get the logs:

```
docker service logs interfold_cn1
```

Notice the line:

```
interfold_cn2.1.zom4r645ophf@nixos    | 2024-12-19T23:47:08.582536Z  INFO interfold: COMPILATION ID: 'painfully_fluent_crane'
```

This can help you identify which compilation you are looking at. This works by generating a unique
ID based on the complication time.
