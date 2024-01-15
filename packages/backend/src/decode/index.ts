import { getEnv, Logger } from '@l2beat/backend-tools'
import { ProjectId, UnixTime } from '@l2beat/shared-pure'
import { ethers } from 'ethers'

import { getConfig } from '../config'
import { Database } from '../peripherals/database/shared/Database'
import { analyzeTransaction } from './analyze'
import { decodeOpStackSequencerBatch } from './decode'
import { FinalityRepository } from './FinalityRepository'
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
  if (process.argv.length !== 4) {
    printHelpAndExit()
  }
  const projectId = process.argv[2]
  const targetTimestamp = process.argv[3]
  return { projectId, targetTimestamp }
}

function printHelpAndExit(): never {
  console.log('USAGE: yarn decode [project_id] [timestamp]')
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
  const tx_hash = await finalityRepository.findByProjectIdAndTimestamp(
    ProjectId(projectId),
    new UnixTime(Number(targetTimestamp)),
    1,
  )
  console.log(tx_hash)
  const alchemyKey = getEnv().string('FINALITY_ALCHEMY_KEY')
  const rpcUrl = `https://eth-mainnet.alchemyapi.io/v2/${alchemyKey}`
  const provider = new ethers.providers.JsonRpcProvider(rpcUrl)
  const { data, timestamp } = await analyzeTransaction(provider, tx_hash)

  const fourBytesApi = new FourBytesApi()
  await decodeOpStackSequencerBatch(projectId, data, timestamp, fourBytesApi)
}

getTx()
  .then(() => {
    process.exit(1)
  })
  .catch((e) => {
    console.error(e)
  })
