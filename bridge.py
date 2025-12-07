from web3 import Web3
from web3.providers.rpc import HTTPProvider
from web3.middleware import ExtraDataToPOAMiddleware #Necessary for POA chains
from datetime import datetime
import json
import pandas as pd

WARDEN_PRIVATE_KEY = "0x7d722aae9d4bcc131f7248f5da966b6a81ecfc2950f4a0ce0e1dd9720a8f73b5"


def connect_to(chain):
    if chain == 'source':  # The source contract chain is avax
        api_url = f"https://api.avax-test.network/ext/bc/C/rpc" #AVAX C-chain testnet

    if chain == 'destination':  # The destination contract chain is bsc
        api_url = f"https://data-seed-prebsc-1-s1.binance.org:8545/" #BSC testnet

    if chain in ['source','destination']:
        w3 = Web3(Web3.HTTPProvider(api_url))
        # inject the poa compatibility middleware to the innermost layer
        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return w3


def get_contract_info(chain, contract_info):
    """
        Load the contract_info file into a dictionary
        This function is used by the autograder and will likely be useful to you
    """
    try:
        with open(contract_info, 'r')  as f:
            contracts = json.load(f)
    except Exception as e:
        print( f"Failed to read contract info\nPlease contact your instructor\n{e}" )
        return 0
    return contracts[chain]

def send_tx(w3, func):
    """
    Build, sign, and send a transaction for the given contract function call.
    Returns the transaction hash.
    """
    account = w3.eth.account.from_key(WARDEN_PRIVATE_KEY)
    from_addr = account.address

    # Build the transaction
    tx = func.build_transaction({
        "from": from_addr,
        "nonce": w3.eth.get_transaction_count(from_addr),
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id,
        # Gas limit is a guess; adjust if needed
        "gas": 500000
    })

    signed = w3.eth.account.sign_transaction(tx, private_key=WARDEN_PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    print(f"Sent tx: {tx_hash.hex()}")
    return tx_hash



def scan_blocks(chain, contract_info="contract_info.json"):
    """
        chain - (string) should be either "source" or "destination"
        Scan the last 5 blocks of the source and destination chains
        Look for 'Deposit' events on the source chain and 'Unwrap' events on the destination chain
        When Deposit events are found on the source chain, call the 'wrap' function the destination chain
        When Unwrap events are found on the destination chain, call the 'withdraw' function on the source chain
    """

    # This is different from Bridge IV where chain was "avax" or "bsc"
    if chain not in ['source','destination']:
        print( f"Invalid chain: {chain}" )
        return 0

    # Load contract infos for both sides
    src_info = get_contract_info("source", contract_info)
    dst_info = get_contract_info("destination", contract_info)

    # Create web3 + contract objects
    w3_source = connect_to("source")
    w3_dest   = connect_to("destination")

    source_contract = w3_source.eth.contract(
        address=Web3.to_checksum_address(src_info["address"]),
        abi=src_info["abi"]
    )
    dest_contract = w3_dest.eth.contract(
        address=Web3.to_checksum_address(dst_info["address"]),
        abi=dst_info["abi"]
    )

    txs_sent = 0

    if chain == "source":
        # We are scanning the SOURCE chain (Avalanche) for Deposit events
        latest_block = w3_source.eth.block_number
        from_block = max(latest_block - 5, 0)

        print(f"Scanning source chain from block {from_block} to {latest_block} for Deposit events")

        deposit_filter = source_contract.events.Deposit.createFilter(
            fromBlock=from_block,
            toBlock=latest_block
        )
        events = deposit_filter.get_all_entries()

        for ev in events:
            args = ev["args"]
            token     = args["token"]
            recipient = args["recipient"]
            amount    = args["amount"]

            print(f"Found Deposit: token={token}, recipient={recipient}, amount={amount}")

            # Call wrap() on the DESTINATION chain
            func = dest_contract.functions.wrap(
                token,
                recipient,
                amount
            )
            send_tx(w3_dest, func)
            txs_sent += 1

    elif chain == "destination":
        # We are scanning the DESTINATION chain (BSC) for Unwrap events
        latest_block = w3_dest.eth.block_number
        from_block = max(latest_block - 5, 0)

        print(f"Scanning destination chain from block {from_block} to {latest_block} for Unwrap events")

        unwrap_filter = dest_contract.events.Unwrap.createFilter(
            fromBlock=from_block,
            toBlock=latest_block
        )
        events = unwrap_filter.get_all_entries()

        for ev in events:
            args = ev["args"]
            underlying = args["underlying_token"]
            to_addr    = args["to"]
            amount     = args["amount"]

            print(f"Found Unwrap: underlying={underlying}, to={to_addr}, amount={amount}")

            # Call withdraw() on the SOURCE chain
            func = source_contract.functions.withdraw(
                underlying,
                to_addr,
                amount
            )
            send_tx(w3_source, func)
            txs_sent += 1

    return txs_sent

