/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { ethers } from 'ethers'
import zlib from 'zlib'

import { add0x } from './utils'

export function decodeBytes(bytes: Buffer, submissionTimestamp: number) {
  const inflated = zlib.inflateSync(bytes)

  // ----- reading decompressed data -----
  const buffer = Buffer.from(inflated)
  const totalLength = buffer.toString('hex').length / 2
  const lengthBytes = ethers.utils.hexlify(totalLength).slice(2)
  const lengthBytesLength = lengthBytes.length / 2
  const lengthByte = 0xf7 + lengthBytesLength
  const lengthByteHex = ethers.utils.hexlify(lengthByte)
  const concatenatedWithLength =
    lengthByteHex + lengthBytes + buffer.toString('hex')
  const decoded = ethers.utils.RLP.decode(concatenatedWithLength)

  const timestamps = []
  for (const [, batch] of decoded.entries()) {
    const decodedBatch = ethers.utils.RLP.decode(add0x(batch.slice(4)))
    const numTxs = decodedBatch[decodedBatch.length - 1].length
    if (numTxs !== 0) {
      const timestamp = parseInt(decodedBatch[3], 16)
      timestamps.push(timestamp)
    }
  }
  const min = submissionTimestamp - Math.min(...timestamps)
  const max = submissionTimestamp - Math.max(...timestamps)
  console.log('Finality delay between', min, 'and', max, 'seconds')
  return {
    minimumFinalityDelay: min,
    maximumFinalityDelay: max,
  }
}
