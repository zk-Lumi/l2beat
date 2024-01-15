import { assert } from '@l2beat/shared-pure'
import { providers } from 'ethers'

export async function analyzeTransaction(
  provider: providers.Provider,
  txHash: string,
) {
  const tx = await provider.getTransaction(txHash)
  assert(tx.blockNumber, 'Block number not found')
  const block = await provider.getBlock(tx.blockNumber)

  return {
    data: tx.data,
    timestamp: block.timestamp,
  }
}
