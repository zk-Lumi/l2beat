import { getEnv, Logger } from '@l2beat/backend-tools'
import { UnixTime } from '@l2beat/shared-pure'

import { getConfig } from '../config'
import { Database } from '../peripherals/database/shared/Database'
import { decodeArbitrum } from './arbitrum/decodeArbitrum'
import { FinalityRepository } from './FinalityRepository'
import { decodeLinea } from './linea/decodeLinea'
import { decodeOPStack } from './OPStack/decodeOPStack'
import { decodePolygonZkEVM } from './polygonzkevm/decodePolygonZkEVM'
import { decodeStarknet } from './starknet/decodeStarknet'
import { decodezkSyncEra } from './zksyncera/decodezkSyncEra'
import { decodezkSyncLite } from './zksynclite/decodezkSyncLite'

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

  let i = 0

  while (true) {
    const tmp = UnixTime.fromDate(new Date('2024-01-14T00:00:00.000Z')).add(
      -(i * 10),
      'minutes',
    )
    console.log(tmp.toDate().toISOString())
    switch (projectId) {
      case 'aevo':
      case 'optimism':
      case 'base':
      case 'lyra':
      case 'publicgoodsnetwork':
      case 'kroma':
      case 'zora':
        await decodeOPStack(
          finalityRepository,
          alchemyKey,
          projectId,
          tmp.toNumber().toString(),
        )
        break
      case 'arbitrum':
        await decodeArbitrum(finalityRepository, alchemyKey, targetTimestamp)
        break
      case 'linea':
        await decodeLinea(
          finalityRepository,
          alchemyKey,
          tmp.toNumber().toString(),
        )
        break
      case 'zksyncera':
        await decodezkSyncEra(
          finalityRepository,
          alchemyKey,
          tmp.toNumber().toString(),
        )
        break
      case 'polygonzkevm':
        await decodePolygonZkEVM(
          finalityRepository,
          alchemyKey,
          tmp.toNumber().toString(),
        )
        break
      case 'zksynclite':
        await decodezkSyncLite(
          finalityRepository,
          alchemyKey,
          tmp.toNumber().toString(),
        )
        break
      case 'starknet':
        await decodeStarknet(
          finalityRepository,
          alchemyKey,
          tmp.toNumber().toString(),
        )
        break
      default:
        throw new Error(`Unknown project id: ${projectId}`)
    }
    i++
  }
}

getTx()
  .then(() => {
    process.exit(0)
  })
  .catch((e) => {
    console.error(e)
  })
