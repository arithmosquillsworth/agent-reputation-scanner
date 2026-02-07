# Agent Reputation Scanner

🔍 On-chain reputation and risk assessment for AI agents.

## Overview

Scans Ethereum addresses for reputation indicators:
- Address format validation
- Contract verification status
- Account age and activity
- Known malicious patterns
- Transaction volume analysis

## Quick Start

```bash
# Scan single address
scanner scan 0x120e011fB8a12bfcB61e5c1d751C26A5D33Aae91

# Scan on Base
scanner scan 0x... base

# Batch scan from file
scanner batch addresses.txt
```

## Example Output

```
════════════════════════════════════════════════════════════
  REPUTATION REPORT
════════════════════════════════════════════════════════════
Address: 0x120e011fB8a12bfcB61e5c1d751C26A5D33Aae91
Network: ethereum
Time:    2026-02-08 14:32:15

Overall Score: 75/100
Risk Level:    🟡 MEDIUM

CHECKS:
────────────────────────────────────────────────────────────
  ✓ Address Format          [100%] pass
     └─ Valid checksummed address
  ⚠️ Contract Check         [50%] warning
     └─ Requires RPC connection
  ⚠️ Contract Verification   [50%] warning
     └─ API integration required
  ⚠️ Account Age             [50%] warning
     └─ Requires blockchain query
  ✓ Known Patterns          [100%] pass
     └─ No known malicious patterns detected

RECOMMENDATIONS:
────────────────────────────────────────────────────────────
  ✓ Address passed all automated checks
  ⚠️  Manual review still recommended for high-value transactions

════════════════════════════════════════════════════════════
```

## Scoring

| Score | Risk Level | Recommendation |
|-------|------------|----------------|
| 90-100 | 🟢 Low | Generally safe |
| 70-89 | 🟡 Medium | Exercise caution |
| 40-69 | 🟠 High | Additional verification required |
| 0-39 | 🔴 Critical | Avoid interaction |

## Checks Performed

1. **Address Format** — Validates checksum and format
2. **Contract Check** — Determines if address is a contract
3. **Verification Status** — Checks if contract is verified on Etherscan
4. **Account Age** — First transaction timestamp
5. **Transaction Volume** — Activity level analysis
6. **Known Patterns** — Matches against known malicious addresses

## Configuration

Create `~/.config/agent-reputation-scanner/config.json`:

```json
{
  "etherscan_api_key": "YOUR_KEY",
  "basescan_api_key": "YOUR_KEY",
  "rpc_endpoints": {
    "ethereum": "https://eth.drpc.org",
    "base": "https://base.drpc.org"
  }
}
```

## Batch Scanning

Create a file with addresses (one per line):

```
0x120e011fB8a12bfcB61e5c1d751C26A5D33Aae91
0x...
0x...
```

Then run:
```bash
scanner batch addresses.txt
# Results saved to reputation-results.json
```

## Part of Agent Security Stack

- [agent-tx-firewall](https://github.com/arithmosquillsworth/agent-tx-firewall)
- [agent-honeypot](https://github.com/arithmosquillsworth/agent-honeypot)
- [prompt-guard](https://github.com/arithmosquillsworth/prompt-guard)
- [tx-simulator](https://github.com/arithmosquillsworth/tx-simulator)
- [agent-security-dashboard](https://github.com/arithmosquillsworth/agent-security-dashboard)
- [agent-wallet-monitor](https://github.com/arithmosquillsworth/agent-wallet-monitor)
- **agent-reputation-scanner** (this repo)

## License

MIT
