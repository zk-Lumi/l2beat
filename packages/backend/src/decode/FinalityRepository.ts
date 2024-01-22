import { Logger } from '@l2beat/backend-tools'
import { LivenessType, ProjectId, UnixTime } from '@l2beat/shared-pure'

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
    type: LivenessType,
    place: number,
  ): Promise<string> {
    const knex = await this.knex()
    let rows
    if (place < 0) {
      rows = await knex('liveness as l')
        .join('liveness_configuration as c', 'l.liveness_id', 'c.id')
        .select('l.tx_hash', 'l.timestamp')
        .where('c.project_id', projectId.toString())
        .andWhere('c.type', type.toString())
        .andWhere('l.timestamp', '>', date.toDate())
        .orderBy('l.timestamp', 'asc')
        .distinct('l.tx_hash')
        .limit(1)
    } else {
      rows = await knex('liveness as l')
        .join('liveness_configuration as c', 'l.liveness_id', 'c.id')
        .select('l.tx_hash', 'l.timestamp')
        .where('c.project_id', projectId.toString())
        .andWhere('c.type', type.toString())
        .andWhere('l.timestamp', '<=', date.toDate())
        .orderBy('l.timestamp', 'desc')
        .distinct('l.tx_hash')
        .limit(1)
        .offset(place)
    }

    return (rows[0] as { tx_hash: string }).tx_hash
  }
}
