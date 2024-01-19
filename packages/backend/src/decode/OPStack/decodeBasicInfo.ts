import assert from 'assert'

export type BasicInfo =
  | {
      type: 'NO_FIRST_FRAME'
      is_last: true
      channelId: string
      frameNumber: number
      bytes: Buffer
    }
  | {
      type: 'NO_END_FRAME'
      is_last: false
      channelId: string
      frameNumber: number
      bytes: Buffer
    }
  | {
      type: 'WHOLE_FRAME'
      is_last: true
      channelId: string
      frameNumber: number
      bytes: Buffer
    }

export function decodeBasicInfo(kind: string, data: string): BasicInfo {
  console.log('Decoding', kind, 'L1 Sequencer transaction batch ...')
  let offset = 0
  const buffer = Buffer.from(data.slice(2), 'hex')
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
  if (frame_number === 0 && is_last === '00') {
    return {
      type: 'NO_END_FRAME',
      is_last: false,
      channelId,
      frameNumber: frame_number,
      bytes,
    }
  } else if (frame_number === 1 && is_last === '01') {
    return {
      type: 'NO_FIRST_FRAME',
      is_last: true,
      channelId,
      frameNumber: frame_number,
      bytes,
    }
  } else {
    return {
      type: 'WHOLE_FRAME',
      is_last: true,
      channelId,
      frameNumber: frame_number,
      bytes,
    }
  }
}
