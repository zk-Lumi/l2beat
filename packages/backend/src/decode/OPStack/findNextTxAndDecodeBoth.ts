import { LivenessType, ProjectId, UnixTime } from '@l2beat/shared-pure'

import { analyzeTransaction } from '../analyze'
import { FinalityRepository } from '../FinalityRepository'
import { BasicInfo, decodeBasicInfo } from './decodeBasicInfo'
import { decodeBytes } from './decodeBytes'

export async function findNextTxAndDecodeBoth(
  alchemyKey: string,
  finalityRepository: FinalityRepository,
  projectId: string,
  targetTimestamp: string,
  firstTxBasicInfo: BasicInfo,
  currentTxCount: number,
): Promise<
  | 'SKIP'
  | {
      minimumFinalityDelay: number
      maximumFinalityDelay: number
    }
> {
  const next_tx_hash = await finalityRepository.findByProjectIdAndTimestamp(
    ProjectId(projectId),
    new UnixTime(Number(targetTimestamp)),
    LivenessType('DA'),
    currentTxCount - 1,
  )
  console.log('next_tx_hash', next_tx_hash)
  const { data, timestamp } = await analyzeTransaction(alchemyKey, next_tx_hash)
  const nextTxResult = decodeBasicInfo(projectId, data)
  // if the next tx has the same channelId and has a type of NO_FIRST_FRAME, decode both txs together
  if (
    firstTxBasicInfo.channelId === nextTxResult.channelId &&
    nextTxResult.type === 'NO_FIRST_FRAME'
  ) {
    const combinedBytes = Buffer.concat([
      firstTxBasicInfo.bytes,
      nextTxResult.bytes,
    ])
    return decodeBytes(combinedBytes, timestamp)
  } else {
    return 'SKIP'
  }
}
