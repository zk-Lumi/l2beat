import { LivenessType, ProjectId, UnixTime } from '@l2beat/shared-pure'

import { analyzeTransaction } from '../analyze'
import { FinalityRepository } from '../FinalityRepository'
import { BasicInfo, decodeBasicInfo } from './decodeBasicInfo'
import { decodeBytes } from './decodeBytes'

export async function findPreviousTxAndDecodeBoth(
  alchemyKey: string,
  finalityRepository: FinalityRepository,
  projectId: string,
  targetTimestamp: string,
  firstTxBasicInfo: BasicInfo,
  lastTxTimestamp: number,
  currentTxCount: number,
): Promise<
  | 'SKIP'
  | {
      minimumFinalityDelay: number
      maximumFinalityDelay: number
    }
> {
  const previous_tx_hash = await finalityRepository.findByProjectIdAndTimestamp(
    ProjectId(projectId),
    new UnixTime(Number(targetTimestamp)),
    LivenessType('DA'),
    currentTxCount + 1,
  )
  const { data } = await analyzeTransaction(alchemyKey, previous_tx_hash)
  const previousTxResult = decodeBasicInfo(projectId, data)
  // if the previous tx has the same channelId and has a type of NO_END_FRAME, decode both txs together
  if (
    firstTxBasicInfo.channelId === previousTxResult.channelId &&
    previousTxResult.type === 'NO_END_FRAME'
  ) {
    const combinedBytes = Buffer.concat([
      previousTxResult.bytes,
      firstTxBasicInfo.bytes,
    ])
    return decodeBytes(combinedBytes, lastTxTimestamp)
  } else {
    return 'SKIP'
  }
}
