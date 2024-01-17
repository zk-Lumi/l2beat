import { getEnv, Logger } from '@l2beat/backend-tools'
import { ProjectId, UnixTime } from '@l2beat/shared-pure'
import { ethers } from 'ethers'

import { getConfig } from '../config'
import { Database } from '../peripherals/database/shared/Database'
import { analyzeTransaction } from './analyze'
import { decodeBasicInfo } from './decode'
import { decodeBytes } from './decodeBytes'
import { FinalityRepository } from './FinalityRepository'
import { findNextTxAndDecodeBoth } from './findNextTxAndDecodeBoth'
import { findPreviousTxAndDecodeBoth } from './findPreviousTxAndDecodeBoth'
import { FourBytesApi } from './FourBytesApi'

const config = getConfig()
const loggerOptions = { ...config.logger }

let logger = new Logger(loggerOptions)
if (config.logThrottler) {
  logger = logger.withThrottling(config.logThrottler)
}

const database = new Database(config.database.connection, config.name, logger, {
  minConnectionPoolSize: config.database.connectionPoolSize.min,
  maxConnectionPoolSize: config.database.connectionPoolSize.max,
})

const finalityRepository = new FinalityRepository(database, logger)

function getArgs() {
  if (process.argv.length !== 3 && process.argv.length !== 4) {
    printHelpAndExit()
  }
  const projectId = process.argv[2]
  const targetTimestamp = process.argv[3] || UnixTime.now().toString()
  return { projectId, targetTimestamp }
}

function printHelpAndExit(): never {
  console.log('USAGE: yarn decode [project_id] [timestamp(optional)]')
  process.exit(1)
}

async function getTx() {
  const { projectId, targetTimestamp } = getArgs()
  await database.assertRequiredServerVersion()
  if (config.database.freshStart) {
    await database.rollbackAll()
  }
  await database.migrateToLatest()

  if (
    config.logger.logLevel === 'DEBUG' ||
    config.logger.logLevel === 'TRACE'
  ) {
    database.enableQueryLogging()
  }

  const alchemyKey = getEnv().string('FINALITY_ALCHEMY_KEY')
  const rpcUrl = `https://eth-mainnet.alchemyapi.io/v2/${alchemyKey}`
  const provider = new ethers.providers.JsonRpcProvider(rpcUrl)
  const fourBytesApi = new FourBytesApi()

  let run = true
  let tx = 0

  while (run) {
    const tx_hash = await finalityRepository.findByProjectIdAndTimestamp(
      ProjectId(projectId),
      new UnixTime(Number(targetTimestamp)),
      tx,
    )
    console.log(tx_hash)

    const { data, timestamp } = await analyzeTransaction(provider, tx_hash)

    const result = decodeBasicInfo(projectId, data)
    console.log(result.type)
    // if there is no second frame, check the next tx
    if (result.type === 'NO_END_FRAME') {
      const res = await findNextTxAndDecodeBoth(
        provider,
        finalityRepository,
        projectId,
        targetTimestamp,
        result,
        fourBytesApi,
        tx,
      )
      if (res === 'SKIP') {
        tx++
        console.log('Skipping tx')
      } else {
        run = false
      }
      // if there is no first frame, check the previous tx
    } else if (result.type === 'NO_FIRST_FRAME') {
      const res = await findPreviousTxAndDecodeBoth(
        provider,
        finalityRepository,
        projectId,
        targetTimestamp,
        result,
        fourBytesApi,
        timestamp,
        tx,
      )
      if (res === 'SKIP') {
        tx++
        console.log('Skipping tx')
      } else {
        run = false
      }
      // if there is only one frame, decode it
    } else {
      await decodeBytes(result.bytes, timestamp, fourBytesApi)
      run = false
    }
  }
}

getTx()
  .then(() => {
    process.exit(0)
  })
  .catch((e) => {
    console.error(e)
  })
