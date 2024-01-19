import { ProjectId, UnixTime } from '@l2beat/shared-pure'
import { ethers, utils } from 'ethers'

import { analyzeTransaction } from '../analyze'
import { FinalityRepository } from '../FinalityRepository'

export async function decodeArbitrum(
  finalityRepository: FinalityRepository,
  alchemyKey: string,
  targetTimestamp: string,
) {
  const tx_hash = await finalityRepository.findByProjectIdAndTimestamp(
    ProjectId('arbitrum'),
    new UnixTime(Number(targetTimestamp)),
    0,
  )
  console.log(tx_hash)

  const { data, timestamp } = await analyzeTransaction(alchemyKey, tx_hash)

  const fnSignature =
    'addSequencerL2BatchFromOrigin(uint256 sequenceNumber,bytes data,uint256 afterDelayedMessagesRead,address gasRefunder,uint256 prevMessageCount,uint256 newMessageCount)'
  const i = new utils.Interface([`function ${fnSignature}`])
  const decodedInput = (
    i.decodeFunctionData(fnSignature, data) as bigint[]
  ).map((x) => x.toString())
  const blockOffset = 22207817
  const prevMessageCount = +decodedInput[4] + 1 + blockOffset
  const newMessageCount = +decodedInput[5] + blockOffset

  const rpcUrl = `https://arb-mainnet.alchemyapi.io/v2/${alchemyKey}`
  const arbitrumProvider = new ethers.providers.JsonRpcProvider(rpcUrl)

  const [prevBlock, newBlock] = await Promise.all([
    arbitrumProvider.getBlock(prevMessageCount),
    arbitrumProvider.getBlock(newMessageCount),
  ])

  console.log(
    'Finality delay between',
    timestamp - prevBlock.timestamp,
    'and',
    timestamp - newBlock.timestamp,
    'seconds',
  )
}
