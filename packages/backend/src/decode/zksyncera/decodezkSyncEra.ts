import { LivenessType, ProjectId, UnixTime } from '@l2beat/shared-pure'
import { utils } from 'ethers'

import { analyzeTransaction } from '../analyze'
import { FinalityRepository } from '../FinalityRepository'

type zkSyncEraDecoded = [
  [number, string, number, number, string, string, number, string][],
]

export async function decodezkSyncEra(
  finalityRepository: FinalityRepository,
  alchemyKey: string,
  targetTimestamp: string,
) {
  const tx_hash = await finalityRepository.findByProjectIdAndTimestamp(
    ProjectId('zksync2'),
    new UnixTime(Number(targetTimestamp)),
    LivenessType('STATE'),
    0,
  )
  console.log(tx_hash)

  const { data, timestamp } = await analyzeTransaction(alchemyKey, tx_hash)

  const fnSignature =
    'executeBatches((uint64,bytes32,uint64,uint256,bytes32,bytes32,uint256,bytes32)[])'
  const i = new utils.Interface([`function ${fnSignature}`])
  const decodedInput = i.decodeFunctionData(
    fnSignature,
    data,
  ) as zkSyncEraDecoded
  const timestamps = decodedInput[0].map((x) => Number(x[6]))

  const min = timestamp - Math.min(...timestamps)
  const max = timestamp - Math.max(...timestamps)
  console.log('Finality delay between', min, 'and', max, 'seconds')
}
