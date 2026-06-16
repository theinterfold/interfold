// Keeps anvil block.timestamp moving during local integration (finalizeCommittee needs
// block.timestamp > committeeDeadline; eth_call-only retries do not mine blocks).

const RPC = process.env.ANVIL_RPC_URL ?? 'http://127.0.0.1:8545'

async function rpc(method, params = []) {
  const res = await fetch(RPC, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  })
  if (!res.ok) {
    throw new Error(`RPC ${method} HTTP ${res.status}`)
  }
  const json = await res.json()
  if (json.error) {
    throw new Error(json.error.message ?? JSON.stringify(json.error))
  }
}

let failureCount = 0
let lastLoggedTime = 0
const LOG_INTERVAL_MS = 30_000

async function loop() {
  for (;;) {
    try {
      await rpc('evm_mine')
      failureCount = 0
    } catch (err) {
      failureCount++
      const now = Date.now()
      if (failureCount === 1 || now - lastLoggedTime >= LOG_INTERVAL_MS) {
        console.error(`[anvil-automine] evm_mine failed (attempt ${failureCount}):`, err)
        lastLoggedTime = now
      }
    }
    await new Promise((r) => setTimeout(r, 1000))
  }
}

loop()
