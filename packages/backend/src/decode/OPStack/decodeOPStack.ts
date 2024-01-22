import { LivenessType, ProjectId, UnixTime } from '@l2beat/shared-pure'

import { analyzeTransaction } from '../analyze'
import { FinalityRepository } from '../FinalityRepository'
import { decodeBasicInfo } from './decodeBasicInfo'
import { decodeBytes } from './decodeBytes'
import { findNextTxAndDecodeBoth } from './findNextTxAndDecodeBoth'
import { findPreviousTxAndDecodeBoth } from './findPreviousTxAndDecodeBoth'

export async function decodeOPStack(
  finalityRepository: FinalityRepository,
  alchemyKey: string,
  projectId: string,
  targetTimestamp: string,
) {
  let run = true
  let txCount = 0

  while (run) {
    const tx_hash = await finalityRepository.findByProjectIdAndTimestamp(
      ProjectId(projectId),
      new UnixTime(Number(targetTimestamp)),
      LivenessType('DA'),
      txCount,
    )
    console.log(tx_hash)

    const { data, timestamp } = await analyzeTransaction(alchemyKey, tx_hash)

    const result = decodeBasicInfo(projectId, data)
    console.log(result.type)
    // if there is no second frame, check the next tx
    if (result.type === 'NO_END_FRAME') {
      const res = await findNextTxAndDecodeBoth(
        alchemyKey,
        finalityRepository,
        projectId,
        targetTimestamp,
        result,
        txCount,
      )
      if (res === 'SKIP') {
        txCount++
        console.log('Skipping tx')
      } else {
        run = false
      }
      // if there is no first frame, check the previous tx
    } else if (result.type === 'NO_FIRST_FRAME') {
      const res = await findPreviousTxAndDecodeBoth(
        alchemyKey,
        finalityRepository,
        projectId,
        targetTimestamp,
        result,
        timestamp,
        txCount,
      )
      if (res === 'SKIP') {
        txCount++
        console.log('Skipping tx')
      } else {
        run = false
      }
      // if there is only one frame, decode it
    } else {
      decodeBytes(result.bytes, timestamp)
      run = false
    }
  }
}
