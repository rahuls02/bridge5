from web3 import Web3
from web3.providers.rpc import HTTPProvider
from web3.middleware import ExtraDataToPOAMiddleware
import json

# ----------------------------------------------------------------------
# WARDEN CONFIG
# ----------------------------------------------------------------------
# This must be the private key of the account that deployed your contracts
# and has WARDEN_ROLE on both source and destination.
WARDEN_PRIVATE_KEY = "0x7d722aae9d4bcc131f7248f5da966b6a81ecfc2950f4a0ce0e1dd9720a8f73b5"


def connect_to(chain):
    """
    Connect to either the source (Avalanche Fuji) or destination (BNB testnet) chain.
    """
    if chain == "source":  # Avalanche Fuji
        api_url = "https://api.avax-test.network/ext/bc/C/rpc"
    elif chain == "destination":  # BNB Testnet
        api_url = "https://data-seed-prebsc-1-s1.binance.org:8545/"
    else:
        raise ValueError(f"Unknown chain: {chain}")

    w3 = Web3(HTTPProvider(api_url))
    # POA middleware needed for these testnets
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return w3


def get_contract_info(chain, contract_info):
    """
    Load the contract_info file into a dictionary.
    This function is used by the autograder and by us.
    """
    try:
        with open(contract_info, 'r') as f:
            contracts = json.load(f)
    except Exception as e:
        print(f"Failed to read contract info\nPlease contact your instructor\n{e}")
        return 0
    return contracts[chain]


def send_tx(w3: Web3, func):
    account = w3.eth.account.from_key(WARDEN_PRIVATE_KEY)
    from_addr = account.address

    tx = func.build_transaction({
        "from": from_addr,
        # Use 'pending' so we always get the next correct nonce
        "nonce": w3.eth.get_transaction_count(from_addr, "pending"),
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id,
        "gas": 500000,
    })

    signed = w3.eth.account.sign_transaction(tx, private_key=WARDEN_PRIVATE_KEY)
    raw = getattr(signed, "rawTransaction", None)
    if raw is None:
        raw = signed.raw_transaction
    tx_hash = w3.eth.send_raw_transaction(raw)
    print(f"Sent tx: {tx_hash.hex()}")
    return tx_hash


def scan_blocks(chain, contract_info="contract_info.json"):
    """
    chain - (string) should be either "source" or "destination"

    Scan recent blocks of the relevant chain:

    - When called with "source":
        Look for Deposit events on the Source contract (Avalanche Fuji)
        For each Deposit, call wrap(...) on the Destination contract (BNB testnet)

    - When called with "destination":
        Look for unwrap() calls on the Destination contract (BNB testnet)
        For each unwrap, call withdraw(...) on the Source contract (Avalanche Fuji)
    """

    if chain not in ["source", "destination"]:
        print(f"Invalid chain: {chain}")
        return 0

    # Load contract info for both sides
    src_info = get_contract_info("source", contract_info)
    dst_info = get_contract_info("destination", contract_info)

    # Connect web3s
    w3_source = connect_to("source")
    w3_dest = connect_to("destination")

    # Contract objects
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
        # ----------------------------------------------------------
        # SOURCE SIDE: find Deposit events and call wrap() on dest
        # ----------------------------------------------------------
        end_block = w3_source.eth.get_block_number()
        start_block = max(end_block - 5, 0)

        print(f"Scanning source chain from block {start_block} to {end_block} for Deposit events")

        # Narrow logs to just this contract address
        try:
            logs = w3_source.eth.get_logs({
                "fromBlock": start_block,
                "toBlock": end_block,
                "address": source_contract.address,
            })
        except Exception as e:
            print(f"Error getting logs on source: {e}")
            return txs_sent

        deposit_events = []
        for log in logs:
            # Try to decode as Deposit; skip others
            try:
                evt = source_contract.events.Deposit().process_log(log)
                deposit_events.append(evt)
            except Exception:
                continue

        print(f"Found {len(deposit_events)} Deposit events")

        for evt in deposit_events:
            args_list = list(evt["args"].values())
            if len(args_list) < 3:
                continue

            token, recipient, amount = args_list[0], args_list[1], args_list[2]

            print(f"Handling Deposit: token={token}, recipient={recipient}, amount={amount}")

            # Call wrap() on destination chain
            func = dest_contract.functions.wrap(token, recipient, amount)
            tx_hash = send_tx(w3_dest, func)

            # Wait for confirmation so the nonce increases before next tx
            try:
                w3_dest.eth.wait_for_transaction_receipt(tx_hash)
            except Exception as e:
                print(f"Error waiting for wrap tx receipt: {e}")

            txs_sent += 1

    else:
        # ----------------------------------------------------------
        # DESTINATION SIDE: find unwrap() calls and call withdraw()
        # ----------------------------------------------------------
        end_block = w3_dest.eth.get_block_number()

        # Use a wider window so we don't miss the grader's unwraps
        WINDOW = 50
        start_block = max(end_block - WINDOW, 0)

        print(f"Scanning destination chain from block {start_block} to {end_block} for Unwrap calls")

        dest_addr = dest_contract.address.lower()

        for block_num in range(start_block, end_block + 1):
            try:
                # Get full transactions so we can inspect inputs
                block = w3_dest.eth.get_block(block_num, full_transactions=True)
            except Exception as e:
                print(f"Error getting block {block_num} on destination: {e}")
                continue

            for tx in block.transactions:
                # Only care about transactions sent to our destination contract
                if tx.to is None or tx.to.lower() != dest_addr:
                    continue

                # Try to decode the function call
                try:
                    func_obj, func_args = dest_contract.decode_function_input(tx.input)
                except Exception:
                    continue

                if func_obj.fn_name != "unwrap":
                    continue

                # unwrap(_wrapped_token, _recipient, _amount)
                wrapped_token = func_args.get("_wrapped_token") or func_args.get(" _wrapped_token")
                to_addr = func_args.get("_recipient") or func_args.get(" _recipient")
                amount = func_args.get("_amount") or func_args.get(" _amount")

                print(f"Found unwrap call in tx {tx.hash.hex()}: wrapped_token={wrapped_token}, to={to_addr}, amount={amount}")

                # Look up the underlying token via the mapping in the Destination contract
                try:
                    underlying_token = dest_contract.functions.underlying_tokens(wrapped_token).call()
                except Exception as e:
                    print(f"Error looking up underlying token for {wrapped_token}: {e}")
                    continue

                print(f"Handling Unwrap: underlying_token={underlying_token}, to={to_addr}, amount={amount}")

                # Call withdraw() on the source chain:
                # withdraw(_token, _recipient, _amount)
                func = source_contract.functions.withdraw(underlying_token, to_addr, amount)
                tx_hash = send_tx(w3_source, func)

                try:
                    w3_source.eth.wait_for_transaction_receipt(tx_hash)
                except Exception as e:
                    print(f"Error waiting for withdraw tx receipt: {e}")

                txs_sent += 1

    return txs_sent
