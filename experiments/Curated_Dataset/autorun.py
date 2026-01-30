from string import Template
import subprocess
import os
import json
from concurrent.futures import ProcessPoolExecutor

config_template = Template("""{
    "fuzzing": {
        "workers": 1,
        "workerResetLimit": 50,
        "timeout": ${timeout},
        "testLimit": 0,
        "shrinkLimit": 500,
        "callSequenceLength": 50,
        "corpusDirectory": "",
        "coverageEnabled": false,
        "fitnessMetricConfig": {
            "codeCoverageEnabled": ${codeCoverageEnabled},
            "branchCoverageEnabled": ${branchCoverageEnabled},
            "storageWriteEnabled": ${storageWriteEnabled},
            "dataflowEnabled": ${dataflowEnabled},
            "branchDistanceEnabled": ${branchDistanceEnabled},
            "cmpDistanceEnabled": ${cmpDistanceEnabled},
            "tokenflowEnabled": ${tokenflowEnabled}         
        },
        "metricRecordConfig": {
            "codeCoverageEnabled": true,
            "branchCoverageEnabled": true,
            "storageWriteEnabled": true,
            "dataflowEnabled": true,
            "branchDistanceEnabled": false,
            "cmpDistanceEnabled": false,
            "tokenflowEnabled": true
        },
        "bugDetectionConfig": {
            "enabled": true,
            "integerOverflow": true,
            "reentrancy": true,
            "etherLeaking": true,
            "suicidal": true,
            "blockDependency": true,
            "unsafeDelegateCall": true
        },
        "targetContracts": [${target_contracts}],
        "targetContractsBalances": [
            ${target_contracts_balances}
        ],
        "constructorArgs": ${constructor_args},
        "deployerAddress": "0x10000",
        "senderAddresses": [
            "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        ],
        "senderAddressBalances": [
            100000000000000000000000000
        ],
        "blockNumberDelayMax": 60480,
        "blockTimestampDelayMax": 604800,
        "blockGasLimit": 125000000,
        "transactionGasLimit": 12500000,
        "testing": {
            "stopOnFailedTest": true,
            "stopOnNoTests": false,
            "testAllContracts": true,
            "traceAll": true,
            "helperContractConfig" : {
                "enabled" : true
            },
            "assertionTesting" : {
                "enabled": false
            },
            "propertyTesting": {
                "enabled": false
            },
            "optimizationTesting": {
                "enabled": false
            }
        },
        "chainConfig": {
            "codeSizeCheckDisabled": true,
            "cheatCodes": {
                "cheatCodesEnabled": true,
                "enableFFI": false
            },
            "SkipAccountChecks": true,
            "forkconfig": {
                "forkModeEnabled": false,
                "rpcUrl": "http://localhost:18545",
                "rpcBlock": 18730462,
                "poolSize": 20
            },
            "stateOverrides": {
                "0xD87a566b05882a29B629B036A4dbf6cBd519bd2D": {
                    "balance": "0xde0b6b3a7640000"
                }
            }
        }
    },
    "compilation": {
        "platform": "crytic-compile",
        "platformConfig": {
            "target": ".",
            "solcVersion": "${solc_version}",
            "exportDirectory": "",
            "args": [],
            "force": false
        }
    },
    "logging": {
        "level": "info",
        "logDirectory": "",
        "noColor": true
    }
}""")

data_config = {}
with open("dataset_config.json", "r") as f:
    data_config = json.load(f)

def run_smartfitness(config_type, t, i, total, contract, path):
    id = "/".join(path.split('/')[-2:])

    id = id.replace(".sol", "")
    # print(id)
    print(f'Running {config_type} {t} {i+1}/{total}: {contract} in {id}')

    target_contracts_balances = '"0x0"'
    target_contracts = ""
    solc_version = "0.4.25"
    constructor_args = "{}"
    if id in data_config:
        target_contracts = f'"{data_config[id]['main_name']}"'
        solc_version = data_config[id]["solc_version"]
        constructor_args = json.dumps(
            {f"{data_config[id]['main_name']}": data_config[id]["constructor_args"]}
        )
        if "constructor_value" in data_config[id]:
            target_contracts_balances = f'"{data_config[id]["constructor_value"]}"'

    # print(id, target_contracts, solc_version)

    type_dir = f'./results/{config_type}'
    if not os.path.exists(type_dir):
        os.mkdir(type_dir)

    dir = f'{type_dir}/{contract}'

    if os.path.exists(dir):
        print(f'{config_type} {t} {i+1}/{total}: {contract} already exists, skipping')
        return
    os.mkdir(dir)

    cache_path = "cache-crytic-exports"
    if os.path.exists(f'{cache_path}/{contract}'):
        subprocess.run(['ln', '-s', f'{cache_path}/{contract}', f'{dir}/crytic-export'])

    options = {
        "codeCoverageEnabled": "false",
        "branchCoverageEnabled": "false",
        "storageWriteEnabled": "false",
        "dataflowEnabled": "false",
        "branchDistanceEnabled": "false",
        "cmpDistanceEnabled": "false",
        "tokenflowEnabled": "false",

        # target contracts
        "target_contracts": target_contracts,
        "target_contracts_balances": target_contracts_balances,  

        # solc version
        "solc_version" : solc_version,

        # constructor params
        "constructor_args": constructor_args,

        # timeout
        "timeout" : 600       
    }

    if config_type == "none":
        pass
    else:
        options[config_type + 'Enabled'] = 'true'

    config = config_template.substitute(options)
    with open(f'{dir}/config.json', 'w') as config_file:
        config_file.write(config)
    
    with open(f'{dir}/stdout.log', 'w') as stdout, open(f'{dir}/stderr.log', 'w') as stderr:
        subprocess.run(['../../../../../smartseed', 'fuzz', '--compilation-target', f'{path}', '--config', './config.json'], stdout=stdout, stderr=stderr, text=True, cwd=dir)

DATASET_PATH = 'dataset'

contracts = []
contract_paths = []

vuln_types = os.listdir(DATASET_PATH)
for vuln_type in vuln_types:
    files = os.listdir(f'{DATASET_PATH}/{vuln_type}')
    for file in files:
        if file.endswith('.sol'):
            contracts.append(f'{vuln_type}_{file[:-4]}')
            contract_paths.append(f'{DATASET_PATH}/{vuln_type}/{file}')

config_types = ['none', "codeCoverage", "branchCoverage", "storageWrite", "dataflow", "branchDistance", "cmpDistance", "tokenflow"]

# with ProcessPoolExecutor(max_workers=1) as executor:
#     for t in range(0, 1):
#         for i, (contract, path) in enumerate(zip(contracts, contract_paths)):
#             for config_type in config_types:
#                 executor.submit(run_smartfitness, config_type, t, i, len(contracts), contract, path)

for t in range(0, 1):
    for i, (contract, path) in enumerate(zip(contracts, contract_paths)):
        for config_type in config_types:
            run_smartfitness(config_type, t, i, len(contracts), contract, path)
