#! /bin/bash

# Get the current git branch.
GIT_REF=$(git rev-parse --abbrev-ref HEAD)

# Define the list of CPU workloads.
CPU_WORKLOADS=(
    # "fibonacci-17k"
    # "ssz-withdrawals"
    # "tendermint"
    # "rsp-20526624"
    # "rsa"
    # "regex"
    # "chess"
    # "json"
    # "blobstream-01j6z63fgafrc8jeh0k12gbtvw"
    # "blobstream-01j6z95bdme9svevmfyc974bja"
    # "blobstream-01j6z9ak0ke9srsppgywgke6fj"
    # "vector-01j6xsv35re96tkgyda115320t"
    # "vector-01j6xzy366ff5tbkzcrs8pma02"
    # "vector-01j6y06de0fdaafemr8b1t69z3"
    # "raiko-a7-10"  
)

# Define the list of CUDA workloads.
CUDA_WORKLOADS=(
    # "fibonacci-17k"
    # "ssz-withdrawals"
    # "tendermint"
    # "rsp-20526624"
    # "rsa"
    # "regex"
    # "chess"
    # "json"
    # "blobstream-01j6z63fgafrc8jeh0k12gbtvw"
    # "blobstream-01j6z95bdme9svevmfyc974bja"
    # "blobstream-01j6z9ak0ke9srsppgywgke6fj"
    # "vector-01j6xsv35re96tkgyda115320t"
    # "vector-01j6xzy366ff5tbkzcrs8pma02"
    # "vector-01j6y06de0fdaafemr8b1t69z3"
    # "raiko-a7-10"   
)

# Define the list of network workloads.
NETWORK_WORKLOADS=(
    "blobstream-01j6z63fgafrc8jeh0k12gbtvw"
    "blobstream-01j6z95bdme9svevmfyc974bja"
    "blobstream-01j6z9ak0ke9srsppgywgke6fj"
    "blobstream-01j6z9bysje9ssrw1dn4w0w9h5"
    "blobstream-01j6zbcx2veyp83r8t6wdhbjsh"
    "blobstream-01j6zbe2srf1krf9zw5yxe4xrw"
    "blobstream-01j6zdrp6xeypb8fbz04v5b6pr"
    "blobstream-01j6ze0690eypaqv7wp1qf34v3"
    "chess"
    "ecdsa-verify"
    "eddsa-verify"
    "fibonacci-17k"
    "fibonacci-1b"
    "fibonacci-200k"
    "fibonacci-200m"
    "fibonacci-20k"
    "fibonacci-20m"
    "fibonacci-2b"
    "fibonacci-2m"
    "fibonacci-400m"
    "fibonacci-40m"
    "fibonacci-4b"
    "fibonacci-4m"
    "groth16-proof-verify"
    "helios"
    "json"
    "keccak256-100kb"
    "keccak256-10mb"
    "keccak256-1mb"
    "keccak256-300kb"
    "keccak256-3mb"
    "loop-100k"
    "loop-100m"
    "loop-10k"
    "loop-10m"
    "loop-1m"
    "loop-300m"
    "loop-30m"
    "loop-3m"
    "loop100k"
    "loop100m"
    "loop10k"
    "loop10m"
    "loop1m"
    "loop30m"
    "loop3m"
    "op-succinct-chain-10-128926200-128926215"
    "op-succinct-chain-10-128926215-128926230"
    "op-succinct-chain-10-128926230-128926245"
    "op-succinct-chain-10-128926245-128926260"
    "op-succinct-chain-10-128926260-128926275"
    "op-succinct-chain-10-128926275-128926290"
    "op-succinct-chain-10-128926290-128926305"
    "op-succinct-chain-10-128926305-128926320"
    "op-succinct-chain-10-128926320-128926335"
    "op-succinct-chain-10-128926335-128926350"
    "op-succinct-chain-10-128926350-128926365"
    "op-succinct-chain-10-128926365-128926380"
    "op-succinct-chain-10-128926380-128926395"
    "op-succinct-chain-10-128926395-128926410"
    "op-succinct-chain-10-128926410-128926425"
    "op-succinct-chain-10-128926425-128926440"
    "op-succinct-chain-10-128926440-128926455"
    "op-succinct-chain-10-128926455-128926470"
    "op-succinct-chain-10-128926470-128926485"
    "op-succinct-chain-10-128926485-128926500"
    "op-succinct-chain-10-128926500-128926515"
    "op-succinct-chain-10-128926515-128926530"
    "op-succinct-chain-10-128926530-128926545"
    "op-succinct-chain-10-128926545-128926560"
    "op-succinct-chain-10-128926560-128926575"
    "op-succinct-chain-10-128926575-128926590"
    "op-succinct-chain-10-128926590-128926605"
    "op-succinct-chain-10-128926605-128926620"
    "op-succinct-chain-10-128926620-128926635"
    "op-succinct-chain-10-128926635-128926650"
    "op-succinct-chain-10-128926650-128926665"
    "op-succinct-chain-10-128926665-128926680"
    "op-succinct-chain-10-128926680-128926695"
    "op-succinct-chain-10-128926695-128926710"
    "op-succinct-chain-10-128926710-128926725"
    "op-succinct-chain-10-128926725-128926740"
    "op-succinct-chain-10-128926740-128926755"
    "op-succinct-chain-10-128926755-128926770"
    "op-succinct-chain-10-128926770-128926785"
    "op-succinct-chain-10-128926785-128926800"
    "op-succinct-chain-10-range-128922202-128922222"
    "op-succinct-chain-10-range-128922242-128922262"
    "op-succinct-chain-10-range-128922262-128922282"
    "op-succinct-chain-10-range-128922282-128922302"
    "op-succinct-chain-10-range-128926100-128926115"
    "op-succinct-chain-10-range-128926115-128926130"
    "op-succinct-chain-10-range-128926130-128926145"
    "op-succinct-chain-10-range-128926145-128926160"
    "op-succinct-chain-10-range-128926160-128926175"
    "op-succinct-chain-10-range-128926175-128926190"
    "op-succinct-chain-10-range-128926190-128926200"
    "op-succinct-chain-480-7086789-7086799"
    "op-succinct-chain-480-7086799-7086809"
    "op-succinct-chain-480-7086809-7086819"
    "op-succinct-chain-480-7086819-7086829"
    "op-succinct-chain-480-7086829-7086839"
    "op-succinct-chain-480-7086839-7086849"
    "op-succinct-chain-480-7086849-7086859"
    "op-succinct-chain-480-7086859-7086869"
    "op-succinct-chain-480-7086869-7086879"
    "op-succinct-chain-480-7086879-7086889"
    "op-succinct-op-sepolia-1818303090-18303120"
    "op-succinct-op-sepolia-18200000-18200030"
    "op-succinct-op-sepolia-18250000-18250030"
    "op-succinct-op-sepolia-18300000-18300040"
    "op-succinct-op-sepolia-18300041-18300081"
    "op-succinct-op-sepolia-18300082-18300122"
    "op-succinct-op-sepolia-18300123-18300163"
    "op-succinct-op-sepolia-18300164-18300204"
    "op-succinct-op-sepolia-18300205-18300245"
    "op-succinct-op-sepolia-18300246-18300286"
    "op-succinct-op-sepolia-18300287-18300300"
    "op-succinct-op-sepolia-18300300-18300340"
    "op-succinct-op-sepolia-18300341-18300381"
    "op-succinct-op-sepolia-18300382-18300422"
    "op-succinct-op-sepolia-18300423-18300463"
    "op-succinct-op-sepolia-18300464-18300504"
    "op-succinct-op-sepolia-18300505-18300545"
    "op-succinct-op-sepolia-18300546-18300586"
    "op-succinct-op-sepolia-18300587-18300627"
    "op-succinct-op-sepolia-18300628-18300668"
    "op-succinct-op-sepolia-18300669-18300709"
    "op-succinct-op-sepolia-18300710-18300750"
    "op-succinct-op-sepolia-18300751-18300791"
    "op-succinct-op-sepolia-18300792-18300832"
    "op-succinct-op-sepolia-18300833-18300873"
    "op-succinct-op-sepolia-18300874-18300914"
    "op-succinct-op-sepolia-18300915-18300955"
    "op-succinct-op-sepolia-18300956-18300996"
    "op-succinct-op-sepolia-18300997-18301037"
    "op-succinct-op-sepolia-18301038-18301078"
    "op-succinct-op-sepolia-18301079-18301119"
    "op-succinct-op-sepolia-18301120-18301160"
    "op-succinct-op-sepolia-18301161-18301201"
    "op-succinct-op-sepolia-18301202-18301242"
    "op-succinct-op-sepolia-18301243-18301283"
    "op-succinct-op-sepolia-18301284-18301300"
    "op-succinct-op-sepolia-18301300-18301340"
    "op-succinct-op-sepolia-18301341-18301381"
    "op-succinct-op-sepolia-18301382-18301422"
    "op-succinct-op-sepolia-18301423-18301463"
    "op-succinct-op-sepolia-18301464-18301504"
    "op-succinct-op-sepolia-18301505-18301545"
    "op-succinct-op-sepolia-18301546-18301586"
    "op-succinct-op-sepolia-18301587-18301627"
    "op-succinct-op-sepolia-18301628-18301668"
    "op-succinct-op-sepolia-18301669-18301709"
    "op-succinct-op-sepolia-18301710-18301750"
    "op-succinct-op-sepolia-18301751-18301791"
    "op-succinct-op-sepolia-18301792-18301832"
    "op-succinct-op-sepolia-18301833-18301873"
    "op-succinct-op-sepolia-18301874-18301914"
    "op-succinct-op-sepolia-18301915-18301955"
    "op-succinct-op-sepolia-18301956-18301996"
    "op-succinct-op-sepolia-18301997-18302037"
    "op-succinct-op-sepolia-18302038-18302078"
    "op-succinct-op-sepolia-18302079-18302119"
    "op-succinct-op-sepolia-18302120-18302160"
    "op-succinct-op-sepolia-18302161-18302201"
    "op-succinct-op-sepolia-18302202-18302242"
    "op-succinct-op-sepolia-18302243-18302283"
    "op-succinct-op-sepolia-18302284-18302324"
    "op-succinct-op-sepolia-18302325-18302365"
    "op-succinct-op-sepolia-18302366-18302406"
    "op-succinct-op-sepolia-18302407-18302447"
    "op-succinct-op-sepolia-18302448-18302488"
    "op-succinct-op-sepolia-18302489-18302529"
    "op-succinct-op-sepolia-18302530-18302570"
    "op-succinct-op-sepolia-18302571-18302611"
    "op-succinct-op-sepolia-18302612-18302652"
    "op-succinct-op-sepolia-18302653-18302693"
    "op-succinct-op-sepolia-18302694-18302734"
    "op-succinct-op-sepolia-18302735-18302775"
    "op-succinct-op-sepolia-18302776-18302816"
    "op-succinct-op-sepolia-18302817-18302857"
    "op-succinct-op-sepolia-18302858-18302898"
    "op-succinct-op-sepolia-18302899-18302939"
    "op-succinct-op-sepolia-18302940-18302980"
    "op-succinct-op-sepolia-18302981-18303000"
    "op-succinct-op-sepolia-18303044-18303074"
    "op-succinct-op-sepolia-range-17685896-17685897"
    "op-succinct-op-sepolia-range-17985900-17985905"
    "op-succinct-op-sepolia-range-18129400-18129401"
    "proofrequest_01jabrkdjfeykrekt9xxns1mg7_v3_0_0_rc4"
    "proofrequest_01jabz7w1tef1a16q75fa3mft0_v3_0_0_rc4"
    "raiko-a7-10"
    "regex"
    "reth"
    "rsa"
    "rsp-20526624-patched"
    "rsp-20526624"
    "rsp-20526626"
    "rsp-20526627"
    "rsp-20526628"
    "rsp-20526629"
    "rsp-20526630"
    "rsp-20528708"
    "rsp-20528709"
    "rsp-20528710"
    "rsp-20528711"
    "rsp-20528712"
    "rsp-20600000"
    "rsp-example"
    "sha256-100kb"
    "sha256-10mb"
    "sha256-1mb"
    "sha256-20k"
    "sha256-300kb"
    "sha256-3mb"
    "ssz-withdrawals"
    "tendermint"
    "vector-01j6xsv35re96tkgyda115320t"
    "vector-01j6xzy366ff5tbkzcrs8pma02"
    "vector-01j6y06de0fdaafemr8b1t69z3"
    "vector-01j6y0en9pfdab5whxq2k60fqs"
    "vector-01j6y0q023edftg2z0d3cj1bgh"
    "vector-01j6y0zfh4edftww00rt660w3q"
    "vector-01j6y176ykff5vcpxwa8gk1vbd"
)

# Create a JSON object with the list of workloads.
WORKLOADS=$(jq -n \
    --arg cpu "$(printf '%s\n' "${CPU_WORKLOADS[@]}" | jq -R . | jq -s 'map(select(length > 0))')" \
    --arg cuda "$(printf '%s\n' "${CUDA_WORKLOADS[@]}" | jq -R . | jq -s 'map(select(length > 0))')" \
    --arg network "$(printf '%s\n' "${NETWORK_WORKLOADS[@]}" | jq -R . | jq -s 'map(select(length > 0))')" \
    '{cpu_workloads: $cpu, cuda_workloads: $cuda, network_workloads: $network}')

# Run the workflow with the list of workloads.
echo $WORKLOADS | gh workflow run suite.yml --ref $GIT_REF --json
