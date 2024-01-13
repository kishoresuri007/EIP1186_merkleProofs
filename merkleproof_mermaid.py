import sha3
import requests
import json
import rlp
from sha3 import keccak_256
from decimal import Decimal, getcontext

def keccak_hash(addr):
    k = sha3.keccak_256()
    k.update(addr)
    return k.hexdigest()

def get_account_proof(node_rpc, eth_address, block_height_hex):
    data = {"jsonrpc":"2.0","method":"eth_getProof","params": [eth_address,[],block_height_hex],"id":1}
    headers = {'Content-type': 'application/json'}
    response = requests.post(node_rpc, data=json.dumps(data), headers=headers)
    return response.json()

def decode_rlp_and_hash(nodes):
    decoded_nodes = []
    hash_nodes = []
    for node in nodes:
        decoded_node = rlp.decode(bytes.fromhex(node[2:])) # node[2:] to remove '0x'
        decoded_node = [part.hex() for part in decoded_node]
        decoded_nodes.append(decoded_node)
        hash_node = keccak_256(bytes.fromhex(node[2:])).hexdigest()
        hash_nodes.append(hash_node)
        print(f'Keccak256 Hash: {hash_node}')
        print(f'Decoded RLP: {decoded_node}')
    return decoded_nodes, hash_nodes

def generate_mermaid(decoded_nodes, hash_nodes):

    mermaid_code = f'---\ntitle: Merkle Proof for account state for keccak({eth_address}) - {keccak_hash(address)}\n---\n\n'
    mermaid_code += "graph TB\n"

    for i in range(len(decoded_nodes)-1):
        shortened_hashes = [part[:6]+'...' for part in decoded_nodes[i]]
        if len(shortened_hashes) == 2:
            mermaid_code += f'Node{i}["Extension Node {i} - {hash_nodes[i]}\n{", ".join(shortened_hashes)}"] --> Node{i+1}\n'
        else:
            mermaid_code += f'Node{i}["Branch Node {i} - {hash_nodes[i]}\n{", ".join(shortened_hashes)}"] --> Node{i+1}\n'
    
    # Adding the leaf node
    shortened_hashes = [part[:6]+'...' for part in decoded_nodes[-1]]
    mermaid_code += f'Node{len(decoded_nodes)-1}["Leaf Node {len(decoded_nodes)-1} - {hash_nodes[-1]}\n{", ".join(decoded_nodes[-1])}"]\n'
    
    # Setting colors
    colors = ["#f9d0c4", "#f2b5d4", "#eea2ad", "#f58518", "#ff6037"] 
    for i in range(len(decoded_nodes)):
        mermaid_code += f'style Node{i} fill:{colors[i%len(colors)]}\n'
    return mermaid_code

node_rpc = 'https://eth-mainnet.g.alchemy.com/v2/[API_KEY]'
eth_address = "0x54aee16C9EFeF4580EA7bC2A713bB24E12675d5d"
block_height = 18985133
address = bytes.fromhex(eth_address[2:])
#print(keccak_hash(address))
block_height_hex = hex(block_height)
account_proof = get_account_proof(node_rpc, eth_address,block_height_hex)
branch_nodes = account_proof['result']['accountProof'] # this assumes the response structure contains 'accountProof'

decoded_nodes, hash_nodes = decode_rlp_and_hash(branch_nodes)

#validate merkle proof manually
mermaid_code = generate_mermaid(decoded_nodes, hash_nodes)
print(mermaid_code)

account_state = rlp.decode(bytes.fromhex(decoded_nodes[-1][1]))
account_state_hex = [part.hex() for part in account_state]
print("Account state: ", account_state_hex)
print("\n")

# Set the precision.
getcontext().prec = 28

hex_balance = account_state_hex[1] # Hexadecimal balance
print("Account balance in hex:", hex_balance)
wei_balance = Decimal(int(hex_balance, 16)) # Convert to Wei (in decimal)
eth_balance = wei_balance / Decimal(10**18) # Convert to Ether
print(f'Balance: {eth_balance} ETH')
