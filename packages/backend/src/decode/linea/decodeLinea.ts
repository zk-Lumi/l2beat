import { LivenessType, ProjectId, UnixTime } from '@l2beat/shared-pure'
import { utils } from 'ethers'

import { analyzeTransaction } from '../analyze'
import { FinalityRepository } from '../FinalityRepository'

type LineaDecoded = [
  [string, number, string, unknown[], string, unknown[]][],
  string,
  number,
  string,
]

export async function decodeLinea(
  finalityRepository: FinalityRepository,
  alchemyKey: string,
  targetTimestamp: string,
) {
  const tx_hash = await finalityRepository.findByProjectIdAndTimestamp(
    ProjectId('linea'),
    new UnixTime(Number(targetTimestamp)),
    // Linea posts everything in the same tx, but we store it only once in STATE type txs
    LivenessType('STATE'),
    0,
  )
  console.log(tx_hash)

  const { data, timestamp } = await analyzeTransaction(alchemyKey, tx_hash)

  const fnSignature =
    'finalizeBlocks((bytes32,uint32,bytes[],bytes32[],bytes,uint16[])[], bytes, uint256, bytes32)'
  const i = new utils.Interface([`function ${fnSignature}`])
  const decodedInput = i.decodeFunctionData(fnSignature, data) as LineaDecoded
  const timestamps = decodedInput[0].map((x) => x[1])

  const min = timestamp - Math.min(...timestamps)
  const max = timestamp - Math.max(...timestamps)
  console.log('Finality delay between', min, 'and', max, 'seconds')
}
