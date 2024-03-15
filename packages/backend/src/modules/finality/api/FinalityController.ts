import { FinalityApiResponse, UnixTime } from '@l2beat/shared-pure'
import { keyBy, mapValues, partition } from 'lodash'

import { FinalityProjectConfig } from '../../../config/features/finality'
import { LivenessRepository } from '../../tracked-txs/modules/liveness/repositories/LivenessRepository'
import { FinalityRepository } from '../repositories/FinalityRepository'
import { calcAvgsPerProject } from './calcAvgsPerProject'
import { divideAndAddLag } from './divideAndAddLag'

type FinalityResult = {
  type: 'success'
  data: FinalityApiResponse
}

export class FinalityController {
  constructor(
    private readonly livenessRepository: LivenessRepository,
    private readonly finalityRepository: FinalityRepository,
    private readonly projects: FinalityProjectConfig[],
  ) {}

  async getFinality(): Promise<FinalityResult> {
    const projects: FinalityApiResponse['projects'] = {}

    const [OPStackProjects, otherProjects] = partition(
      this.projects,
      (p) => p.type === 'OPStack',
    )
    const OPStackFinality = await this.getOPStackFinality(OPStackProjects)
    Object.assign(projects, OPStackFinality)

    const projectsFinality = await this.getProjectsFinality(otherProjects)
    Object.assign(projects, projectsFinality)

    return { type: 'success', data: { projects } }
  }

  async getProjectsFinality(
    projects: FinalityProjectConfig[],
  ): Promise<FinalityApiResponse['projects']> {
    const projectIds = projects.map((p) => p.projectId)
    const records = await this.finalityRepository.getLatestGroupedByProjectId(
      projectIds,
    )

    const result: FinalityApiResponse['projects'] = mapValues(
      keyBy(records, 'projectId'),
      (record) => ({
        timeToInclusion: {
          minimumInSeconds: record.minimumTimeToInclusion,
          maximumInSeconds: record.maximumTimeToInclusion,
          averageInSeconds: record.averageTimeToInclusion,
        },
        syncedUntil: record.timestamp,
      }),
    )

    return result
  }

  async getOPStackFinality(
    projects: FinalityProjectConfig[],
  ): Promise<FinalityApiResponse['projects']> {
    const result: FinalityApiResponse['projects'] = {}
    await Promise.all(
      projects.map(async (project) => {
        const records = await this.livenessRepository.getByProjectIdAndType(
          project.projectId,
          'batchSubmissions',
          UnixTime.now().add(-1, 'days'),
        )

        const latestRecord = records.at(0)
        if (!latestRecord) return

        const intervals = calcAvgsPerProject(records)
        const projectResult = divideAndAddLag(intervals, project.lag)
        const syncedUntil = latestRecord.timestamp

        if (projectResult) {
          result[project.projectId.toString()] = {
            timeToInclusion: projectResult,
            syncedUntil,
          }
        }
      }),
    )
    return result
  }
}
