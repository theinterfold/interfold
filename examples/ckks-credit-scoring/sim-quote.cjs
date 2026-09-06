// Simulate getE3Quote with the REAL struct ABI, sweeping the start buffer,
// to identify which validateRequest branch rejects the credit server's request.
const { createPublicClient, http, parseAbi } = require('viem');

const INTERFOLD = '0x8198f5d8F8CfFE8f9C413d98a0A55aEB8ab9FbB7';
const PROGRAM = '0xD8a5a9b31c3C0232E196d518E89Fd8bF83AcAd43';

const abi = parseAbi([
  'struct E3RequestParams { uint8 committeeSize; uint256[2] inputWindow; address e3Program; uint8 paramSet; bytes computeProviderParams; bytes customParams; }',
  'function getE3Quote(E3RequestParams requestParams) view returns (uint256)',
]);

(async () => {
  const c = createPublicClient({ transport: http('http://127.0.0.1:8545') });
  for (const buf of [20, 60, 120, 300]) {
    const block = await c.getBlock();
    const now = Number(block.timestamp);
    const start = now + buf;
    const params = {
      committeeSize: 0,
      inputWindow: [BigInt(start), BigInt(start + 300)],
      e3Program: PROGRAM,
      paramSet: 4,
      computeProviderParams: '0x',
      customParams: '0x',
    };
    try {
      const fee = await c.readContract({ address: INTERFOLD, abi, functionName: 'getE3Quote', args: [params] });
      console.log(`buffer ${buf}s: OK fee=${fee}`);
    } catch (e) {
      const reason = e.cause?.reason ?? e.cause?.data?.errorName ?? e.shortMessage;
      console.log(`buffer ${buf}s: FAILED ${reason}`);
    }
  }
})();
