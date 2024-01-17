/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { ethers } from 'ethers'
import zlib from 'zlib'

import { FourBytesApi } from './FourBytesApi'
import { add0x, trimLong } from './utils'

export async function decodeBytes(
  bytes: Buffer,
  submissionTimestamp: number,
  fourBytesApi: FourBytesApi,
) {
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

  let numEmptyBatches = 0
  console.log('Decoding', decoded.length, 'batches')

  const timestamps = []
  for (const [index, batch] of decoded.entries()) {
    // batch: batch_version ++ rlp (parent_hash, epoch_number, epoch_hash, timestamp, transaction_list)
    const decodedBatch = ethers.utils.RLP.decode(add0x(batch.slice(4)))
    const numTxs = decodedBatch[decodedBatch.length - 1].length
    if (numTxs !== 0) {
      // transaction list is not empty
      console.log()
      console.log('Batch #', index, 'with', numTxs, 'transactions')
      console.log('ParentHash', decodedBatch[0])
      console.log('EpochNumber', parseInt(decodedBatch[1], 16))
      console.log('EpochHash', decodedBatch[2])
      const timestamp = parseInt(decodedBatch[3], 16)
      console.log('Timestamp', timestamp)
      timestamps.push(timestamp)

      for (const tx of decodedBatch[decodedBatch.length - 1]) {
        //console.log('tx:', tx)
        const parsed = ethers.utils.parseTransaction(tx)
        const methodHash = parsed.data.slice(0, 10)
        await Promise.resolve(setTimeout(() => {}, 1000))
        const methodSignature = await fourBytesApi.getMethodSignature(
          methodHash,
        )
        console.log('  ', trimLong(tx), methodHash, methodSignature)
      }
    } else numEmptyBatches++
  }
  console.log('Num of empty batches', numEmptyBatches)
  console.log(
    'Finality delay between',
    submissionTimestamp - Math.min(...timestamps),
    'and',
    submissionTimestamp - Math.max(...timestamps),
    'seconds',
  )
}
