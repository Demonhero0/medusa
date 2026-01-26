# SmartFitness

`smartfitness` is a unified fuzzing framework for [go-ethereum](https://github.com/ethereum/go-ethereum/)-based smart contracts. 

Based on [medusa](https://github.com/crytic/medusa), `smartfitness` supports flexible evaluation of test seeds using a variety of fitness metrics, enabling easy integration and comparative analysis of different fitness metrics within the same framework, whose implementation is in `fuzzing/fitnessmetrics`. Second, it implement several bug oracles in `fuzzing/bugdetector`, making it support detecting common bugs like Reentrancy and Integer Overflows.

## Install

```
bash build.sh
```

## Usage

### Loacl Testing

Run the command for execution, where `--config` is the path of config file, `--compilation-target` is the `.sol` file to compile, `--target-contracts` is the names of the contracts to test.

```
./smartfitness fuzz --config example/config.json --compilation-target example.sol --target-contracts Example
```

### On-chain Testing

If you want to test the smart contracts deployed on chain, set the on-chain mode in config file (e.g., `example/config_onchain.json`).

```
    "forkconfig": {
        "forkModeEnabled": true, // Turn on for on-chain testing
        "rpcUrl": "http://localhost:18545", // Archive nodes that provide RPC services
        "rpcBlock": 9894152, // The similuated block height
        "poolSize": 20
    }
```

After that, run the command for execution.
```
./smartfitness fuzz --config example/config_onchain.json
```

## Batch run for experiments

### Experiments on Curated Dataset

Run the following command, the experimental results will be stored in `experiments/Curated_Dataset/results`
```
cd experiments/Curated_Dataset
python3 autorun.py
```

### Experiments on DeFiHackLabs Dataset

Set the on-chain mode in `experiments/DeFiHackLabs_Dataset/autorun.py`
```
    "forkconfig": {
        "forkModeEnabled": true, // Turn on for on-chain testing
        "rpcUrl": "http://localhost:18545", // Archive nodes that provide RPC services
        ...
    }
```

Run the following command, the experimental results will be stored in `experiments/DeFiHackLabs_Dataset/results`

```
cd experiments/DeFiHackLabs_Dataset
python3 autorun.py
```

## License

`smartfitness` is licensed and distributed under the [AGPLv3](./LICENSE).