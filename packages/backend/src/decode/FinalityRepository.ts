import { Logger } from '@l2beat/backend-tools'
import { ProjectId, UnixTime } from '@l2beat/shared-pure'

import {
  BaseRepository,
  CheckConvention,
} from '../peripherals/database/shared/BaseRepository'
import { Database } from '../peripherals/database/shared/Database'

export class FinalityRepository extends BaseRepository {
  constructor(database: Database, logger: Logger) {
    super(database, logger)
    this.autoWrap<CheckConvention<FinalityRepository>>(this)
  }

  async findByProjectIdAndTimestamp(
    projectId: ProjectId,
    date: UnixTime,
    place: number,
  ): Promise<string> {
    const knex = await this.knex()
    const rows = await knex('liveness as l')
      .join('liveness_configuration as c', 'l.liveness_id', 'c.id')
      .select('l.tx_hash', 'l.timestamp')
      .where('c.project_id', projectId.toString())
      .andWhere('c.type', 'DA')
      .andWhere('l.timestamp', '<=', date.toDate())
      .orderBy('l.timestamp', 'desc')
      .limit(1)
      .offset(place - 1)

    return (rows[0] as { tx_hash: string }).tx_hash
  }
}
