import { HttpClient } from '@l2beat/shared'
import { LivenessType, ProjectId, UnixTime } from '@l2beat/shared-pure'
import { utils } from 'ethers'

import { StarknetClient } from '../../peripherals/starknet/StarknetClient'
import { analyzeTransaction } from '../analyze'
import { FinalityRepository } from '../FinalityRepository'

type StarknetDecoded = [number[], number, number]

export async function decodeStarknet(
  finalityRepository: FinalityRepository,
  alchemyKey: string,
  targetTimestamp: string,
) {
  const tx_hash = await finalityRepository.findByProjectIdAndTimestamp(
    ProjectId('starknet'),
    new UnixTime(Number(targetTimestamp)),
    LivenessType('STATE'),
    0,
  )
  console.log(tx_hash)

  const { data, timestamp } = await analyzeTransaction(alchemyKey, tx_hash)

  const fnSignature =
    'updateState(uint256[] programOutput,uint256 onchainDataHash,uint256 onchainDataSize)'
  const i = new utils.Interface([`function ${fnSignature}`])
  const decodedInput = i.decodeFunctionData(
    fnSignature,
    data,
  ) as StarknetDecoded
  const blockNumber = Number(decodedInput[0][2])
  const rpcUrl = `https://starknet-mainnet.g.alchemy.com/v2/${alchemyKey}`
  const http = new HttpClient()
  const client = new StarknetClient(rpcUrl, http)

  const block = await client.getBlock(blockNumber)
  console.log('Finality delay', timestamp - block.timestamp, 'seconds')
}
