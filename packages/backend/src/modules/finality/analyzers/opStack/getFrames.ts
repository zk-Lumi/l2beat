import { assert } from '@l2beat/backend-tools'

const VersionOffset = 0
const EncodingVersion = 0

// https://specs.optimism.io/protocol/derivation.html#batcher-transaction-format
export function getFrames(data: Uint8Array) {
  assert(
    data[VersionOffset] === EncodingVersion,
    `Invalid version received, expected ${EncodingVersion} received ${data[VersionOffset]}`,
  )

  const frames = data.slice(1)

  // bytes32
  const channelId = '0x' + toNumber(frames.slice(0, 16)).toString(16)
  // uint16
  const frameNumber = toNumber(frames.slice(16, 18))
  // uint32
  const frameDataLength = toNumber(frames.slice(18, 22))
  // bytes
  const frameData = frames.slice(22, 22 + frameDataLength)
  // bool
  const isLast = !!toNumber(
    frames.slice(22 + frameDataLength, 22 + frameDataLength + 1),
  )

  // there can be multiple frames per blob
  assert(frames.length === 22 + frameDataLength + 1, "Invalid frame's length")

  return {
    channelId,
    frameNumber,
    frameDataLength,
    frameData,
    isLast,
  }
}

function toNumber(arr: Uint8Array): number {
  assert(arr.length > 0)

  if (arr.length === 1) {
    return arr[0]
  }

  return 256 * toNumber(arr.slice(0, arr.length - 1)) + arr[arr.length - 1]
}
