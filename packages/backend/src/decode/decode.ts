import assert from 'assert'
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { ethers } from 'ethers'
import zlib from 'zlib'

import { FourBytesApi } from './FourBytesApi'
import { add0x, trimLong } from './utils'

export async function decodeOpStackSequencerBatch(
  kind: string,
  data: string,
  submissionTimestamp: number,
  fourBytesApi: FourBytesApi,
) {
  console.log('Decoding', kind, 'L1 Sequencer transaction batch ...')
  let offset = 0
  let buffer = Buffer.from(data.slice(2), 'hex')
  const version = buffer.subarray(offset, offset + 1).toString('hex')
  console.log('Version:', version)
  offset += 1
  const channelId = buffer.subarray(offset, offset + 16).toString('hex')
  offset += 16
  console.log('ChannelId:', channelId)
  const frame_number = buffer.readUint16BE(offset)
  offset += 2
  console.log('Frame Number:', frame_number)
  const frame_data_length = buffer.readUint32BE(offset)
  offset += 4
  console.log('Frame Data Length:', frame_data_length)

  const bytes = buffer.subarray(offset, offset + frame_data_length)
  offset += frame_data_length
  const is_last = buffer.subarray(offset, offset + 1).toString('hex')
  offset += 1
  assert(is_last === '01' || is_last === '00')
  console.log('Is Last:', is_last === '01')
  const inflated = zlib.inflateSync(bytes)

  // ----- reading decompressed data -----
  buffer = Buffer.from(inflated)
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
