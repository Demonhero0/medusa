from string import Template
import subprocess
import os
import json
import csv
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
        "targetContractsBalances": [],
        "constructorArgs": {},
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
                "forkModeEnabled": true,
                "rpcUrl": "http://localhost:18545",
                "rpcBlock": ${block_number},
                "poolSize": 20
            }
        }
    },
    "logging": {
        "level": "debug",
        "logDirectory": "",
        "noColor": false
    }
}""")


def run_smartfitness(config_types, t, i, total, name, block, addresses):
    config_types_str = "+".join(config_types)
    print(f'Running {config_types_str} {t} {i+1}/{total}: {name}')

    # print(id, target_contracts, solc_version)

    type_dir = f'./results_fusion/{config_types_str}'
    if not os.path.exists(type_dir):
        os.mkdir(type_dir)

    directory = f'{type_dir}/{name}_{t}'
    if os.path.exists(directory):
        print(f'{config_types_str} {t} {i+1}/{total}: {name} already exists, skipping')
        return
    block = int(block)
    addresses = [addr.strip() for addr in addresses.split(';')]
    addresses = ", ".join([f'"{addr}"' for addr in addresses if addr != ''])

    os.mkdir(directory)

    abi_path = "abis"
    if os.path.exists(f'{abi_path}'):
        subprocess.run(['ln', '-s', f'{abi_path}', f'{directory}/abis'])

    options = {
        "codeCoverageEnabled": "false",
        "branchCoverageEnabled": "false",
        "storageWriteEnabled": "false",
        "dataflowEnabled": "false",
        "branchDistanceEnabled": "false",
        "cmpDistanceEnabled": "false",
        "tokenflowEnabled": "false",

        # timeout
        "timeout" : 1800,

        # target_contracts
        "target_contracts" : addresses,
        "block_number": block,
    }

    for config_type in config_types:
        if config_type == "none":
            pass
        else:
            options[config_type + 'Enabled'] = 'true'

    config = config_template.substitute(options)
    with open(f'{directory}/config.json', 'w') as config_file:
        config_file.write(config)
    
    with open(f'{directory}/stdout.log', 'w') as stdout, open(f'{directory}/stderr.log', 'w') as stderr:
        subprocess.run(['../../../../../smartfitness', 'fuzz', '--config', './config.json'], stdout=stdout, stderr=stderr, text=True, cwd=directory)

config_types_list = [
    ["branchCoverage", "branchDistance"],
    ["branchCoverage", "dataflow"],
    ["branchDistance", "storageWrite"],
    ["cmpDistance", "dataflow", "storageWrite"],
    ["branchCoverage", "tokenflow"],
    ["branchCoverage", "storageWrite"]
]


with open('./dapps.csv', 'r', encoding='utf-8') as file:
    csv_reader = csv.reader(file)

    _ = next(csv_reader) # skip the headers
    rows = list(csv_reader)

    # with ProcessPoolExecutor(max_workers=10) as executor:
    #     for t in range(0, 1):
    #         for i, row in enumerate(rows):
    #             for config_types in config_types_list:
    #                 executor.submit(run_smartfitness, config_types, t, i, len(rows), *row)

    for t in range(0, 1):
        for i, row in enumerate(rows):
            for config_type in config_types_list:
                run_smartfitness(config_type, t, i, len(rows), *row)