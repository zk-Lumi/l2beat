import { HttpClient } from '@l2beat/shared'
import { assert, LivenessType, ProjectId, UnixTime } from '@l2beat/shared-pure'

import { analyzeTransaction } from '../analyze'
import { FinalityRepository } from '../FinalityRepository'

export async function decodeLoopring(
  finalityRepository: FinalityRepository,
  alchemyKey: string,
  targetTimestamp: string,
) {
  const tx_hash = await finalityRepository.findByProjectIdAndTimestamp(
    ProjectId('loopring'),
    new UnixTime(Number(targetTimestamp)),
    LivenessType('STATE'),
    0,
  )
  console.log(tx_hash)

  const { timestamp, logs } = await analyzeTransaction(alchemyKey, tx_hash, {
    events: {
      topics: [
        '0xcc86d9ed29ebae540f9d25a4976d4da36ea4161b854b8ecf18f491cf6b0feb5c',
      ],
    },
  })
  const blockNumberHex = logs?.[0].topics[1]
  assert(blockNumberHex, 'No block number found in logs')
  const blockNumber = parseInt(logs[0].topics[1])

  const http = new HttpClient()
  const res = await http.fetch(
    `https://api3.loopring.io/api/v3/block/getBlock?id=${blockNumber}`,
  )
  const result = (await res.json()) as { createdAt: number }
  console.log(
    'Finality delay',
    timestamp - Math.round(result.createdAt / 1000),
    'seconds',
  )
}
