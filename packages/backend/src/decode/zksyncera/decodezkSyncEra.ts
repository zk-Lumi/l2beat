import { LivenessType, ProjectId, UnixTime } from '@l2beat/shared-pure'
import { utils } from 'ethers'

import { analyzeTransaction } from '../analyze'
import { FinalityRepository } from '../FinalityRepository'

type zkSyncEraDecoded = [
  [number, string, number, number, string, string, number, string],
  [number, string, number, number, string, string, number, string][],
  [number[], number[]],
]

export async function decodezkSyncEra(
  finalityRepository: FinalityRepository,
  alchemyKey: string,
  targetTimestamp: string,
) {
  const tx_hash = await finalityRepository.findByProjectIdAndTimestamp(
    ProjectId('zksync2'),
    new UnixTime(Number(targetTimestamp)),
    LivenessType('PROOF'),
    0,
  )
  console.log(tx_hash)

  const { data, timestamp } = await analyzeTransaction(alchemyKey, tx_hash)

  const fnSignature =
    'proveBatches((uint64,bytes32,uint64,uint256,bytes32,bytes32,uint256,bytes32), (uint64,bytes32,uint64,uint256,bytes32,bytes32,uint256,bytes32)[], (uint256[],uint256[]))'
  const i = new utils.Interface([`function ${fnSignature}`])
  const decodedInput = i.decodeFunctionData(
    fnSignature,
    data,
  ) as zkSyncEraDecoded
  const timestamps = []
  timestamps.push(Number(decodedInput[0][6]))
  decodedInput[1].forEach((batch) => {
    timestamps.push(Number(batch[6]))
  })

  const min = timestamp - Math.min(...timestamps)
  const max = timestamp - Math.max(...timestamps)
  console.log('Finality delay between', min, 'and', max, 'seconds')
}
