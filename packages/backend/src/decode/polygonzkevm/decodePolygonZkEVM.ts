import { LivenessType, ProjectId, UnixTime } from '@l2beat/shared-pure'
import { utils } from 'ethers'

import { analyzeTransaction } from '../analyze'
import { FinalityRepository } from '../FinalityRepository'

type PolygonZkEVMDecoded = [[string, string, number, number][], string]

export async function decodePolygonZkEVM(
  finalityRepository: FinalityRepository,
  alchemyKey: string,
  targetTimestamp: string,
) {
  const tx_hash = await finalityRepository.findByProjectIdAndTimestamp(
    ProjectId('polygonzkevm'),
    new UnixTime(Number(targetTimestamp)),
    LivenessType('DA'),
    0,
  )
  console.log(tx_hash)

  const { data, timestamp } = await analyzeTransaction(alchemyKey, tx_hash)

  const fnSignature =
    'sequenceBatches((bytes,bytes32,uint64,uint64)[], address)'
  const i = new utils.Interface([`function ${fnSignature}`])
  const decodedInput = i.decodeFunctionData(
    fnSignature,
    data,
  ) as PolygonZkEVMDecoded
  const timestamps = decodedInput[0].map((x) => x[2])

  const min = timestamp - Math.min(...timestamps)
  const max = timestamp - Math.max(...timestamps)
  console.log('Finality delay between', min, 'and', max, 'seconds')
}
