import sys
import json
import time
import random
import pandas as pd
from web3 import Web3, constants
from pathlib import Path
from web3.middleware import ExtraDataToPOAMiddleware


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def connect_to(chain):
    api_url, w3 = None, None
    if chain == 'avax':
        api_url = f"https://api.avax-test.network/ext/bc/C/rpc"  # AVAX C-chain testnet
    if chain == 'bsc':
        api_url = f"https://data-seed-prebsc-1-s1.binance.org:8545/"  # BSC testnet
    if chain in ['avax', 'bsc']:
        w3 = Web3(Web3.HTTPProvider(api_url))
        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return w3


def get_source_contract(contract_file):
    try:
        with contract_file.open('r')  as f:
            contracts = json.load(f)
    except Exception as e:
        print( f"{bcolors.WARNING}ERROR{bcolors.ENDC}: "
               f"Failed to read deposit contract info\nPlease contact your instructor\n{e}" )
        sys.exit(1)

    return contracts['source']


def get_destination_contract(contract_file):
    try:
        with contract_file.open('r')  as f:
            contracts = json.load(f)
    except Exception as e:
        print( f"{bcolors.WARNING}ERROR{bcolors.ENDC}: "
               f"could not load destination contract info\nPlease contact your instructor" )
        sys.exit(1)

    return contracts['destination']
# def getContractInfo(chain):
#    p = Path(__file__).with_name(contract_info)
#    try:
#        with p.open('r')  as f:
#            contracts = json.load(f)
#    except Exception as e:
#        print( "Failed to read contract info" )
#        print( "Please contact your instructor" )
#        print( e )
#        sys.exit(1)
#
#    return contracts[chain]

########################################
# contract_info = "contract_info.json"
# source_chain = 'avax'
# destination_chain = 'bsc'
# source_w3 = connect_to(source_chain)
# destination_w3 = connect_to(destination_chain)


########################################


def get_erc20s(w3, chain, n, erc20s_file, erc20s_abi_file):
    """
        w3 - web3 instance (connected to the appropriate blockchain)
        chain (string) - which blockchain to use (e.g. 'avax', 'bsc')
        n (integer) - how many contracts to return

        Returns n ERC20 contract objects on the chain given by the 'chain' argument
        It tries to read known contract addresses from the file "erc20s.csv"
        """

    contracts = []
    try:
        df = pd.read_csv(erc20s_file)
        contracts = df.loc[df['chain'] == chain]['address'].unique()
    except Exception as e:
        print(f"{bcolors.WARNING}INCOMPLETE{bcolors.ENDC}: "
              f"unable to read ERC20 contracts\nMake sure you add your "
              f"'erc20s.csv file to your git repo\n{e}")
        sys.exit(1)

    num_deployed = len(contracts)

    if num_deployed < n:
        print(f"{bcolors.WARNING}INCOMPLETE{bcolors.ENDC}: "
              f"You need to deploy {n - num_deployed} more ERC20 contract(s) to {chain}\n"
              f"Or update your 'erc20s.csv' file with the tokens you have deployed")
        n = num_deployed

    # Try to read the ABI from a local file
    if erc20s_abi_file.is_file():
        with open(erc20s_abi_file, 'r') as f:
            erc20_abi = json.load(f)
    else:
        print(f"{bcolors.FAIL}ERROR{bcolors.ENDC}: "
              f"ERC20 ABI file does not exist\nContact your instructor")
        sys.exit(0)

    tokens = [w3.eth.contract(abi=erc20_abi, address=c) for c in contracts[:n]]
    return tokens


def get_eth_keys(filename, keyId = 0):
    """
    Generate a persistent Ethereum account
    keyId (integer) - which key to use
    filename - filename to read and store mnemonics

    Each mnemonic is stored on a separate line
    If fewer than (keyId+1) mnemonics have been generated, generate a new one and return that
    """
    w3 = Web3()
    w3.eth.account.enable_unaudited_hdwallet_features()
    try:
        with open(filename, 'r') as f:
            mnemonic_secrets = f.readlines()
        mnemonic_secret = mnemonic_secrets[keyId].rstrip()
        acct = w3.eth.account.from_mnemonic(mnemonic_secret)

    except Exception as e:
        print(f"{e}\nGenerating account")
        acct,mnemonic_secret = w3.eth.account.create_with_mnemonic()
        print(f"Private key: {acct.key}\nAddress: {acct.address}\nmnemonic: {mnemonic_secret}")
        with open(filename, 'a') as f:
            f.write(mnemonic_secret+"\n")

    return acct


def get_wrapped_token_object(src_token, destination_w3, destination_contract, erc20_abi_file):
    """
        token - (contract object) underlying token on source chain
        Returns a contract object corresponding to the wrapped version of this asset on the destination chain
    """
    try:
        wrapped_token_address = destination_contract.functions.wrapped_tokens(src_token.address).call()
    except Exception as e:
        print(f"Failed to get wrapped token for {src_token.address} on contract {destination_contract.address}\n{e}")
        return None

    try:
        with open(erc20_abi_file, 'r') as f:
            ERC20_ABI = json.load(f)
        wrapped_token = destination_w3.eth.contract(abi=ERC20_ABI, address=wrapped_token_address)
    except Exception as e:
        print(
            f"Failed to create token contract object for {wrapped_token_address} "
            f"on contract {destination_contract.address}\n{e}")
        return None

    return wrapped_token


def sign_and_send(contract, function, signer, argdict, confirm=True, force_nonce=0):
    """
        contract - (contract object) 
        functin - (string) the function to be called on the contract
        signer - (account object) the account that should initiate the transaction
        argdict - (dictionary) the function arguments as key-value pairs
        confirm - (boolean) whether to wait for confirmation from the chain
        force_nonce - (int) signAndSend gets the signer's nonce from on-chain, so if you call it multiple times
        in rapid succession, the later transactions will fail.  This allow you to specify the nonce based on the 
        return from sign_and_send if you know you're going to call the function repeatedly
    """
    w3 = contract.w3
    nonce = w3.eth.get_transaction_count(signer.address)
    if nonce <= force_nonce:
        nonce = force_nonce + 1
    contract_func = getattr(contract.functions, function)
    try:
        tx = contract_func(**argdict).build_transaction(
            {'nonce': nonce, 'gasPrice': w3.eth.gas_price, 'from': signer.address,
             'gas': 10 ** 6})  # Must set gas price (https://github.com/ethereum/web3.py/issues/2307)
    except Exception as e:
        print(f"{bcolors.FAIL}ERROR{bcolors.ENDC}: in sign_and_send, failed to build "
              f"transaction (function = {function})\n{e}")
        return None
    signed_tx = w3.eth.account.sign_transaction(tx, signer.key)

    try:
        w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    except Exception as e:
        print(f"{bcolors.FAIL}ERROR{bcolors.ENDC}: in sign_and_send, failed to send "
              f"transaction (function = {function})\n{e}")
        return None

    if confirm:
        tx_receipt = w3.eth.wait_for_transaction_receipt(signed_tx.hash)
        if tx_receipt.status:
            print(f"{bcolors.OKGREEN}SUCCESS{bcolors.ENDC}: in sign_and_send, Transaction confirmed for '{function}' at block {tx_receipt.blockNumber}")
        else:
            print(f"{bcolors.FAIL}ERROR{bcolors.ENDC}: in sign_and_send, Transaction "
                  f"failed '{function}'\n{signed_tx.hash.hex()}")

    return signed_tx.hash.hex(), nonce


def ensure_balance(token, user, bal, minter):
    """
        token - (contract object) an ERC20 token
        user - (address)
        bal - (int)
        Ensure the address "user" has a balance of at least bal in the ERC20 token.
        If the user's balance is below bal, new tokens are minted
    """

    current_balance = token.functions.balanceOf(user).call()
    if current_balance >= bal:
        return True

    try:
        is_minter = token.functions.hasRole(token.functions.MINTER_ROLE().call(), minter.address)
    except Exception as e:
        print(f"Failed to call 'hasRole'")
        print("Contact your instructor")
        print(e)
        return False

    if not is_minter:
        print(f"{minter.address} is not allowed to mint tokens on {token.address}")
        print("Contact your instructor")
        return False

    print("Grader low on tokens, topping up before we check student contracts")
    print(f"Minting {bal - current_balance} {token.functions.symbol().call()} tokens to {user}")
    sign_and_send(token, 'mint', minter, {'to': user, 'amount': bal - current_balance})


def get_wrapped_token(token, destination_w3, destination_contract, erc20s_abi_file):
    """
        token - (contract object) underlying token on source chain
        Returns a contract object corresponding to the wrapped version of this asset on the destination chain
    """
    try:
        wrapped_token_address = destination_contract.functions.wrapped_tokens(token.address).call()
    except Exception as e:
        print(f"Failed to get wrapped token for {token.address} on contract {destination_contract.address}\n{e}")
        return None

    with open(erc20s_abi_file, 'r') as f:
        erc20_abi = json.load(f)

    try:
        wrapped_token = destination_w3.eth.contract(abi=erc20_abi, address=wrapped_token_address)
    except Exception as e:
        print(f"Failed to create token contract object for {wrapped_token_address} "
              f"on contract {destination_contract.address}\n{e}")
        return None

    return wrapped_token


def check_token_registration(source_contract, deposits, destination_contract, minter):
    """
       check erc20s are registered on contracts
    """
    not_registered = []
    for d in deposits:
        token = d['token']  # Contract object (not address)
        sender = d['sender']  # Account object (not address)

        if not source_contract.functions.approved(token.address).call():
            print(f"\n{bcolors.WARNING}INCOMPLETE{bcolors.ENDC}: you need to call registerToken({token.address})\n"
                  f"Before submitting your assignment")
            not_registered.append(token.address)
        else:
            ensure_balance(token, sender.address, 10 ** 6, minter)

        if constants.ADDRESS_ZERO == destination_contract.functions.wrapped_tokens(token.address).call():
            print(f"\n{bcolors.WARNING}INCOMPLETE{bcolors.ENDC}:  you need to call createToken({token.address})\n"
                  f"Before submitting your assignment")
            not_registered.append(token.address)

    return 0 == len(not_registered)


def check_contract_addresses(source, destination):
    """
        check student provided "contract_info.json" contracts against defaults
    """
    if "0x2849A1F9e4700BEe779232396FD803cdcA7d0cde" == source or \
            "0x99Ab2ae5053244E85BC0fbE1A311740295c2afEc" == destination:
        return False
    return True


def make_deposits(deposits, source_contract):
    """
        deposits - (list of dictionaries)  
        Make deposits on the source chain
    """
    print(f"SourceContract.address = {source_contract.address}")
    nonce = 0
    for d in deposits:
        token = d['token']  # Contract object (not address)
        sender = d['sender']  # Account object (not address)
        receiver = d['receiver']  # address
        amount = d['amount']  # int

        try:
            transaction_hash, nonce = sign_and_send(token,
                                                    "approve", 
                                                    sender,
                                                    {'spender': source_contract.address, 'amount': amount}, 
                                                    force_nonce=nonce)
            print(f"Approval transaction Hash {transaction_hash}\n")
        except Exception as e:
            print(f"{bcolors.FAIL}ERROR{bcolors.ENDC}: Failed to approve token transfer\nContact your instructor\n{e}\n")

        try:
            transaction_hash, nonce = sign_and_send(source_contract,
                                                    "deposit", 
                                                    sender,
                                                    {'_token': token.address, '_recipient': receiver, '_amount': amount},
                                                    force_nonce=nonce)
            print(f"Deposit transaction Hash = {transaction_hash}\n")
        except Exception as e:
            print(f"{bcolors.FAIL}ERROR{bcolors.ENDC}: deposit transaction failed on source chain\n{e}\n")


def make_withdrawals(withdrawals, destination_contract):
    """
        withdrawals - (list of dictionaries)  
        Make withdrawals on the destination chain
    """
    print(f"DestinationContract.address = {destination_contract.address}")
    nonce = 0
    for d in withdrawals:
        token = d['token']  # Contract object of wrapped token (not address)
        sender = d['sender']  # Account object (not address)
        receiver = d['receiver']  # address
        amount = d['amount']  # int

        # No need to approve withdrawal, the bridge can withdraw without approvals to save gas
        try:
            transaction_hash, nonce = sign_and_send(destination_contract, 
                                                    "unwrap", 
                                                    sender,
                                                    {'_wrapped_token': token.address, '_recipient': receiver, '_amount': amount},
                                                    force_nonce=nonce)
            print(f"Unwrap transaction Hash = {transaction_hash}")
        except Exception as e:
            print(f"{bcolors.FAIL}ERROR{bcolors.ENDC}: unwrap transaction failed on destination chain\n{e}\n")


def check_for_wrap(destination_w3, destination_contract):
    end_block = destination_w3.eth.get_block_number()
    start_block = end_block - 20
    print(f"Autograder scanning blocks {start_block} - {end_block} on destination")
    event_filter = destination_contract.events.Wrap.create_filter(from_block=start_block, to_block=end_block,
                                                                  argument_filters={})
    events = event_filter.get_all_entries()
    print(f"Autograder found {len(events)} events")

    wrap_events = []
    for evt in events:
        data = {
            'event': evt.event,  # Wrap
            'block_number': evt.blockNumber,
            'underlying_token': evt.args['underlying_token'],
            'wrapped_token': evt.args['wrapped_token'],
            'to': evt.args['to'],
            'amount': evt.args['amount'],
            'transactionHash': evt.transactionHash.hex(),
            'address': evt.address,
        }
        print(json.dumps(data, indent=2))
        wrap_events.append(data)

    return wrap_events


def check_for_withdrawal(source_w3, source_contract):
    end_block = source_w3.eth.get_block_number()
    start_block = end_block - 20
    print(f"Autograder scanning blocks {start_block} - {end_block} on source")
    event_filter = source_contract.events.Withdrawal.create_filter(from_block=start_block, to_block=end_block,
                                                                   argument_filters={})
    events = event_filter.get_all_entries()
    print(f"Autograder found {len(events)} Withdrawal events")

    withdrawal_events = []
    for evt in events:
        data = {
            'event': evt.event,  # Withdrawal
            'block_number': evt.blockNumber,
            'token': evt.args['token'],
            'recipient': evt.args['recipient'],
            'amount': evt.args['amount'],
            'transactionHash': evt.transactionHash.hex(),
            'address': evt.address,
        }
        print(json.dumps(data, indent=2))
        withdrawal_events.append(data)
    return withdrawal_events


def validate(code_path):

    contract_file = code_path / "contract_info.json"
    erc20s_file = code_path / "erc20s.csv"
    keys_file = Path(__file__).parent.absolute() / "eth_mnemonic.txt"
    erc20s_abi_file = Path(__file__).parent.absolute() / "ERC20ABI.json"
    source_chain = 'avax'
    destination_chain = 'bsc'
    user_a = get_eth_keys(keys_file, keyId=0)
    user_b = get_eth_keys(keys_file, keyId=3)
    minter = get_eth_keys(keys_file, keyId=1)

    print(f"{bcolors.OKCYAN}STARTING GRADER SETUP{bcolors.ENDC}:")
    # Check all required student files are in their repo
    if not erc20s_file.is_file():
        print(f"{bcolors.FAIL}ERROR{bcolors.ENDC}: You are required to have your own\n"
              f"'erc20s.csv' in your git repo")
        sys.exit(1)
    if not contract_file.is_file():
        print(f"{bcolors.FAIL}ERROR{bcolors.ENDC}: You are required to have your own\n"
              f"copy of 'contract_info.json' in your git repo")
        sys.exit(1)

    # Get source contract information
    source_w3 = connect_to(source_chain)
    deposit = get_source_contract(contract_file)
    source_contract = source_w3.eth.contract(abi=deposit['abi'], address=deposit['address'])

    # Get destination contract information
    destination_w3 = connect_to(destination_chain)
    withdrawal = get_destination_contract(contract_file)
    destination_contract = destination_w3.eth.contract(abi=withdrawal['abi'], address=withdrawal['address'])

    # Points awarded for deploying contracts
    setup_points = 0
    print("\n----- AutoGrader checking student has deployed their own contracts -----")
    if not check_contract_addresses(deposit['address'], withdrawal['address']):
        print(f"{bcolors.FAIL}ERROR{bcolors.ENDC}: You are required to deploy your own\n"
              f"source and destination contracts and record\nthe addresses in the copy "
              f"of 'contract_info.json' in your git repo")
        return setup_points
    else:
        print(f"{bcolors.OKGREEN}SUCCESS{bcolors.ENDC}: Contract addresses appear to be valid")
    setup_points += 10  # For deploying own contracts

    # Get the tokens the student reported to have registered
    print("\n----- AutoGrader checking student has registered / created tokens ------")
    num_tokens = 2

    # This line just checks that the student deployed their tokens to the destination side
    get_erc20s(destination_w3, destination_chain, num_tokens, erc20s_file, erc20s_abi_file)

    # Create deposit arg dicts
    tokens = get_erc20s(source_w3, source_chain, 2, erc20s_file, erc20s_abi_file)
    deposits = [
        {'token': token,
         'sender': user_a,
         'receiver': user_b.address,
         'amount': random.randint(10, 1000)} for token in tokens]
    withdrawals = [
        {'token': get_wrapped_token(t['token'], destination_w3, destination_contract, erc20s_abi_file),
         'sender': user_b,
         'receiver': user_a.address,
         'amount': t['amount']} for t in deposits]

    # Verify that the student registered the tokens they recorded in the erc20s.csv
    if not check_token_registration(source_contract, deposits, destination_contract, minter):
        return setup_points
    else:
        print(f"{bcolors.OKGREEN}SUCCESS{bcolors.ENDC}: ERC20s are valid and registered")
    setup_points += 10  # Points for registering tokens

    """
    If the code hasn't returned at this point then the final score
    will be the greater of "setup_points" or
    final score calculation
    """
    print("\n----- AutoGrader sending deposits to student Source contract -----")
    make_deposits(deposits, source_contract)
    time.sleep(5)

    print(f"{bcolors.OKCYAN}GRADER SETUP COMPLETE{bcolors.ENDC}:\n")
    print("\n----- Calling student 'bridge.scan_blocks()' -----")
    try:
        from bridge import scan_blocks
        scan_blocks('source', contract_file)  # Run the student's code
    except Exception as e:
        print(f"{bcolors.FAIL}ERROR{bcolors.ENDC}: running scan_blocks('source')\n{e}")
        return setup_points

    print("\n----- AutoGrader searching for Wrap events on student Destination contract -----")
    time.sleep(5)
    # Now we search the destination chain for Wrap events
    wrap_events = check_for_wrap(destination_w3, destination_contract)
    if len(wrap_events) == 0:
        time.sleep(5)
        wrap_events = check_for_wrap(destination_w3, destination_contract)
    score = 0
    for d in deposits:
        for w in wrap_events:
            if d['receiver'] == w['to'] and d['amount'] == w['amount'] and d['token'].address == w['underlying_token']:
                score += 1
                break
            else:
                print(f"{d['receiver']} ?= {w['to']}\n"
                      f"{d['amount']} ?= {w['amount']}\n"
                      f"{d['token'].address} ?= {w['underlying_token']}")

    ############################################################
    # Now we test the reverse direction
    # We make withdrawals on the destination chain and check if the message gets passed back to the source chain
    print("\n----- AutoGrader sending Unwrap to student Destination contract -----")
    make_withdrawals(withdrawals, destination_contract)
    time.sleep(5)
    print("\n----- Calling student 'bridge.scan_blocks()' -----")
    try:
        from bridge import scan_blocks
        scan_blocks('destination', contract_file)  # Run the student's code
    except Exception as e:
        print(f"{bcolors.FAIL}ERROR{bcolors.ENDC}: running scan_blocks('destination')\n{e}")
        return max((100.0 * (float(score) / (2 * len(deposits)))), setup_points)

    # Now we search the source chain for Withdraw events
    print("\n----- AutoGrader searching for Withdraw events on student Source contract -----")
    time.sleep(5)
    withdrawal_events = check_for_withdrawal(source_w3, source_contract)
    if len(withdrawal_events) == 0:
        time.sleep(5)
        withdrawal_events = check_for_withdrawal(source_w3, source_contract)

    for u in withdrawals:
        for w in withdrawal_events:
            if u['receiver'] == w['recipient'] and \
                    u['amount'] == w['amount'] and \
                    destination_contract.functions.underlying_tokens(u['token'].address).call() == w['token']:
                score += 1
                break
            else:
                print(f"{u['receiver']} ?= {w['recipient']}")
                print(f"{u['amount']} ?= {w['amount']}")
                print(f"{destination_contract.functions.underlying_tokens(u['token'].address).call()} ?= {w['token']}")

    return max((100.0 * (float(score) / (2 * len(deposits)))), setup_points)


if __name__ == "__main__":
    final_score = validate(Path(__file__).parent.absolute())
    print(f"Score = {final_score}")
