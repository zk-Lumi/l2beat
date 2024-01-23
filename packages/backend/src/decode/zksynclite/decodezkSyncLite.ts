import { LivenessType, ProjectId, UnixTime } from '@l2beat/shared-pure'
import { utils } from 'ethers'

import { analyzeTransaction } from '../analyze'
import { FinalityRepository } from '../FinalityRepository'

type zkSyncLiteDecoded = [
  [number, bigint, string, bigint, string, string][],
  [bigint[], bigint[], bigint[], number[], bigint[]],
]

export async function decodezkSyncLite(
  finalityRepository: FinalityRepository,
  alchemyKey: string,
  targetTimestamp: string,
) {
  const tx_hash = await finalityRepository.findByProjectIdAndTimestamp(
    ProjectId('zksync'),
    new UnixTime(Number(targetTimestamp)),
    LivenessType('PROOF'),
    0,
  )
  console.log(tx_hash)

  const { data, timestamp } = await analyzeTransaction(alchemyKey, tx_hash)

  const fnSignature =
    'proveBlocks((uint32,uint64,bytes32,uint256,bytes32,bytes32)[], (uint256[],uint256[],uint256[],uint8[],uint256[16]))'
  const i = new utils.Interface([`function ${fnSignature}`])
  const decodedInput = i.decodeFunctionData(
    fnSignature,
    data,
  ) as zkSyncLiteDecoded
  const timestamps = decodedInput[0].map((b) => Number(b[3]))

  const min = timestamp - Math.min(...timestamps)
  const max = timestamp - Math.max(...timestamps)
  console.log('Finality delay between', min, 'and', max, 'seconds')
}
