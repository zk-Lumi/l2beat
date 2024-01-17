import { ProjectId, UnixTime } from '@l2beat/shared-pure'
import { providers } from 'ethers'

import { analyzeTransaction } from './analyze'
import { BasicInfo, decodeBasicInfo } from './decode'
import { decodeBytes } from './decodeBytes'
import { FinalityRepository } from './FinalityRepository'
import { FourBytesApi } from './FourBytesApi'

export async function findPreviousTxAndDecodeBoth(
  provider: providers.Provider,
  finalityRepository: FinalityRepository,
  projectId: string,
  targetTimestamp: string,
  firstTxBasicInfo: BasicInfo,
  fourBytesApi: FourBytesApi,
  lastTxTimestamp: number,
  currentTxCount: number,
): Promise<'SKIP' | undefined> {
  const previous_tx_hash = await finalityRepository.findByProjectIdAndTimestamp(
    ProjectId(projectId),
    new UnixTime(Number(targetTimestamp)),
    currentTxCount + 1,
  )
  const { data } = await analyzeTransaction(provider, previous_tx_hash)
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
    await decodeBytes(combinedBytes, lastTxTimestamp, fourBytesApi)
  } else {
    return 'SKIP'
  }
}
