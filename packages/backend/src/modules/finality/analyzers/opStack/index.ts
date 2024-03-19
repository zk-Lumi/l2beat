import {
  assert,
  ProjectId,
  TrackedTxsConfigSubtype,
  UnixTime,
} from '@l2beat/shared-pure'
import { utils } from 'ethers'
import { inflate } from 'pako'

import { BlobClient } from '../../../../peripherals/blobclient/BlobClient'
import { RpcClient } from '../../../../peripherals/rpcclient/RpcClient'
import { LivenessRepository } from '../../../tracked-txs/modules/liveness/repositories/LivenessRepository'
import { BaseAnalyzer } from '../types/BaseAnalyzer'
import { blobToData } from './blobToData'
import { decodeSpanBatch } from './decodeSpanBatch'
import { getFrames } from './getFrames'

export class OpStackFinalityAnalyzer extends BaseAnalyzer {
  constructor(
    private readonly blobClient: BlobClient,
    provider: RpcClient,
    livenessRepository: LivenessRepository,
    projectId: ProjectId,
  ) {
    super(provider, livenessRepository, projectId)
  }

  override getTrackedTxSubtype(): TrackedTxsConfigSubtype {
    return 'batchSubmissions'
  }

  async getFinality(transaction: {
    txHash: string
    timestamp: UnixTime
  }): Promise<number[]> {
    const l1Timestamp = transaction.timestamp
    // get blobs relevant to the transaction
    const relevantBlobs = await this.blobClient.getRelevantBlobs(
      transaction.txHash,
    )

    const rollupData = relevantBlobs.map(({ blob }) =>
      blobToData(byteArrfromHexStr(blob)),
    )
    const frames = rollupData.map((ru) => getFrames(ru))
    const channel = assembleChannel(frames)
    const encodedBatch = getBatchFromChannel(channel)
    const blocksWithTimestamps = decodeSpanBatch(encodedBatch)
    const blocksWithDelays = blocksWithTimestamps.map((block) => ({
      txCount: block.txCount,
      delay: l1Timestamp.toNumber() - block.timestamp,
    }))
    // calculate weighted average
    const totalWeight = blocksWithDelays.reduce(
      (acc, block) => acc + block.txCount,
      0,
    )
    const weightedDelays = blocksWithDelays.map(
      (block) => (block.txCount * block.delay) / totalWeight,
    )
    const weightedAverage = weightedDelays.reduce(
      (acc, delay) => acc + delay,
      0,
    )
    return [weightedAverage]
  }
}

function getBatchFromChannel(channel: Uint8Array) {
  const decompressed = inflate(channel)
  const decoded = utils.RLP.decode(decompressed) as unknown

  // we assume decoded is a hex string, meaning it represents only one span batch
  assert(typeof decoded === 'string', 'Decoded is not a string')

  return byteArrfromHexStr(decoded)
}

// async function decompressToByteArray(compressedData: Uint8Array) {
//   // const blob = new Blob([compressedData])
//   // const ds = new DecompressionStream('deflate')
//   // const stream = blob.stream().pipeThrough(ds)
//   // const reader = stream.getReader()
//   // const chunks: Uint8Array[] = []
//   // let totalSize = 0
//   // while (true) {
//   //   try {
//   //     const { done, value } = await reader.read()
//   //     if (done) break
//   //     chunks.push(value)
//   //     totalSize += value.length
//   //   } catch (err) {
//   //     console.log(err)
//   //     break
//   //   }
//   // }
//   // const concatenatedChunks = new Uint8Array(totalSize)
//   // let offset = 0
//   // for (const chunk of chunks) {
//   //   concatenatedChunks.set(chunk, offset)
//   //   offset += chunk.length
//   // }
//   // return concatenatedChunks
// }

function assembleChannel(
  frames: {
    frameData: Uint8Array
    channelId: string
    isLast: boolean
    frameNumber: number
  }[],
) {
  assert(frames.length > 0, 'No frames to assemble')

  // we check if all frames belong to the same channel because it's simple
  // in fact, opstack batcher does not have to send all frames in one blob
  // or in order, so let's assert here and fix it if we need to.
  // do all frames belong to the same channel?
  const channels = new Set(frames.map((frame) => frame.channelId))
  assert(channels.size === 1, 'Frames belong to different channels')

  // is last frame the last one?
  const framesSorted = frames.sort((a, b) => a.frameNumber - b.frameNumber)
  const lastFrame = framesSorted[framesSorted.length - 1]
  assert(lastFrame.isLast, 'Last frame is not the last one')
  assert(framesSorted.length === lastFrame.frameNumber, 'Frames are missing')

  const dataLength = frames.reduce(
    (acc, frame) => acc + frame.frameData.length,
    0,
  )
  const data = new Uint8Array(dataLength)
  let offset = 0
  for (const frame of frames) {
    data.set(frame.frameData, offset)
    offset += frame.frameData.length
  }
  return data
}

function byteArrfromHexStr(hexString: string) {
  const str = hexString.startsWith('0x') ? hexString.slice(2) : hexString
  const match = str.match(/.{1,2}/g)

  assert(match !== null, 'Invalid hex string')

  return Uint8Array.from(match.map((byte) => parseInt(byte, 16)))
}
