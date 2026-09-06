// Simulate requestE3 exactly as the credit server does, to surface the revert reason
// that the JSON-RPC returns as bare "0x".
const { createPublicClient, http, parseAbi, encodeFunctionData } = require('viem');

const INTERFOLD = '0x8198f5d8F8CfFE8f9C413d98a0A55aEB8ab9FbB7';
const PROGRAM = '0xD8a5a9b31c3C0232E196d518E89Fd8bF83AcAd43';
const CALLER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'; // anvil #0
const PARAM_SET = Number(process.env.PS ?? 4);

const abi = parseAbi([
  'function requestE3(uint8 committeeSize, uint256[2] calldata inputWindow, address e3Program, uint8 paramSet, bytes calldata computeProviderParams, bytes calldata customParams) returns (uint256)',
  'function getE3Quote(uint8 committeeSize, uint256[2] calldata inputWindow, address e3Program, uint8 paramSet, bytes calldata computeProviderParams) view returns (uint256)',
]);

(async () => {
  const c = createPublicClient({ transport: http('http://127.0.0.1:8545') });
  const block = await c.getBlock();
  const start = Number(block.timestamp) + 60;
  const win = [BigInt(start), BigInt(start + 300)];

  try {
    const quote = await c.readContract({
      address: INTERFOLD, abi, functionName: 'getE3Quote',
      args: [0, win, PROGRAM, PARAM_SET, '0x'],
    });
    console.log('quote OK:', quote.toString());
  } catch (e) {
    console.log('quote FAILED:', e.shortMessage || e.message);
  }

  try {
    await c.simulateContract({
      address: INTERFOLD, abi, functionName: 'requestE3',
      args: [0, win, PROGRAM, PARAM_SET, '0x', '0x'],
      account: CALLER,
    });
    console.log('requestE3 simulate OK');
  } catch (e) {
    console.log('requestE3 FAILED');
    console.log('  short:', e.shortMessage);
    console.log('  cause:', e.cause?.reason ?? e.cause?.shortMessage ?? e.cause?.data ?? '(none)');
    const meta = e.metaMessages?.slice(0, 6).join('\n  ');
    if (meta) console.log('  meta:\n  ' + meta);
  }
})();
