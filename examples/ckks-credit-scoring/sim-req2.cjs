const { createPublicClient, http } = require('viem');
const j = require(process.env.HOME + '/Documents/zk/interfold/packages/interfold-contracts/artifacts/contracts/Interfold.sol/Interfold.json');
const INTERFOLD = '0x8198f5d8F8CfFE8f9C413d98a0A55aEB8ab9FbB7';
const PROGRAM = '0xD8a5a9b31c3C0232E196d518E89Fd8bF83AcAd43';
const SENDER = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
(async () => {
  const c = createPublicClient({ transport: http('http://127.0.0.1:8545') });
  const b = await c.getBlock();
  const start = Number(b.timestamp) + 90;
  const p = { committeeSize: 0, inputWindow: [BigInt(start), BigInt(start + 300)], e3Program: PROGRAM,
    paramSet: 4, computeProviderParams: '0x', customParams: '0x',
    expectedFeeToken: '0x0000000000000000000000000000000000000000',
    expectedCryptoConfigId: '0x' + '0'.repeat(64), maxFee: 0n };
  try {
    await c.simulateContract({ address: INTERFOLD, abi: j.abi, functionName: "request", args: [p], account: SENDER });
    console.log('requestE3 simulate OK');
  } catch (e) {
    const d = e.cause?.data;
    console.log('requestE3 FAILED:', d?.errorName ?? e.cause?.reason ?? e.shortMessage);
    if (d?.args) console.log('  args:', d.args.map(String).join(', '));
  }
})();
