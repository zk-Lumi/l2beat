import { Logger } from '@l2beat/backend-tools'
import { bridges, layer2s } from '@l2beat/config'
import {
  AssetId,
  cacheAsyncFunction,
  ChainId,
  ProjectAssetsBreakdownApiResponse,
  ProjectId,
  ReportType,
  Token,
  TokenTvlApiChart,
  TokenTvlApiCharts,
  TvlApiChart,
  TvlApiCharts,
  TvlApiResponse,
  UnixTime,
} from '@l2beat/shared-pure'

import { Clock } from '../../../tools/Clock'
import { TaskQueue } from '../../../tools/queue/TaskQueue'
import { ReportProject } from '../reports/ReportProject'
import { AggregatedReportRepository } from '../repositories/AggregatedReportRepository'
import { AggregatedReportStatusRepository } from '../repositories/AggregatedReportStatusRepository'
import { BalanceRepository } from '../repositories/BalanceRepository'
import { PriceRepository } from '../repositories/PriceRepository'
import { ReportRepository } from '../repositories/ReportRepository'
import { asNumber } from './asNumber'
import { getProjectAssetChartData } from './charts'
import { generateTvlApiResponse } from './generateTvlApiResponse'
import { getHourlyMinTimestamp } from './getHourlyMinTimestamp'
import { getSixHourlyMinTimestamp } from './getSixHourlyMinTimestamp'
import {
  getCanonicalAssetsBreakdown,
  getNonCanonicalAssetsBreakdown,
  groupAndMergeBreakdowns,
} from './tvl'
import { Result } from './types'

type ProjectAssetBreakdownResult = Result<
  ProjectAssetsBreakdownApiResponse,
  'DATA_NOT_FULLY_SYNCED' | 'NO_DATA'
>

type TvlResult = Result<TvlApiResponse, 'DATA_NOT_FULLY_SYNCED' | 'NO_DATA'>

type TokenTvlResult = Result<
  TokenTvlApiCharts,
  'INVALID_PROJECT_OR_ASSET' | 'NO_DATA' | 'DATA_NOT_FULLY_SYNCED'
>

type AggregatedTvlResult = Result<
  TvlApiCharts,
  'DATA_NOT_FULLY_SYNCED' | 'NO_DATA' | 'EMPTY_SLUG'
>

export class TvlController {
  private readonly taskQueue: TaskQueue<void>

  getCachedTvlApiResponse: () => Promise<TvlResult>

  constructor(
    private readonly aggregatedReportRepository: AggregatedReportRepository,
    private readonly reportRepository: ReportRepository,
    private readonly aggregatedReportStatusRepository: AggregatedReportStatusRepository,
    private readonly balanceRepository: BalanceRepository,
    private readonly priceRepository: PriceRepository,
    private readonly projects: ReportProject[],
    private readonly tokens: Token[],
    private readonly clock: Clock,
    private readonly logger: Logger,
  ) {
    this.logger = this.logger.for(this)

    const cached = cacheAsyncFunction(() => this.getTvlApiResponse())
    this.getCachedTvlApiResponse = cached.call
    this.taskQueue = new TaskQueue(
      cached.refetch,
      this.logger.for('taskQueue'),
      { metricsId: TvlController.name },
    )
  }

  start() {
    this.taskQueue.addToFront()

    const fiveMinutes = 5 * 60 * 1000
    setInterval(() => {
      this.taskQueue.addIfEmpty()
    }, fiveMinutes)
  }

  async getTvlApiResponse(): Promise<TvlResult> {
    const latestTimestamp = this.clock.getLastHour()

    const [hourlyReports, sixHourlyReports, dailyReports, latestReports] =
      await Promise.all([
        this.aggregatedReportRepository.getHourlyWithAnyType(
          getHourlyMinTimestamp(latestTimestamp),
        ),

        this.aggregatedReportRepository.getSixHourlyWithAnyType(
          getSixHourlyMinTimestamp(latestTimestamp),
        ),

        this.aggregatedReportRepository.getDailyWithAnyType(),

        this.reportRepository.getByTimestamp(latestTimestamp),
      ])

    const projects = []
    for (const project of this.projects) {
      if (project.escrows.length === 0) {
        continue
      }

      const sinceTimestamp = new UnixTime(
        Math.min(
          ...project.escrows.map((escrow) => escrow.sinceTimestamp.toNumber()),
        ),
      )

      projects.push({
        id: project.projectId,
        isLayer2: project.type === 'layer2',
        sinceTimestamp,
      })
    }

    const tvlApiResponse = generateTvlApiResponse(
      hourlyReports,
      sixHourlyReports,
      dailyReports,
      latestReports,
      projects,
      latestTimestamp,
    )

    return { result: 'success', data: tvlApiResponse }
  }

  async getAggregatedTvlApiResponse(
    slugs: string[],
  ): Promise<AggregatedTvlResult> {
    const projectIdsFilter = [...layer2s, ...bridges]
      .filter((project) => !project.isUpcoming)
      .filter((project) => slugs.includes(project.display.slug))
      .map((project) => project.id)

    if (projectIdsFilter.length === 0) {
      return {
        result: 'error',
        error: 'EMPTY_SLUG',
      }
    }

    const latestTimestamp = this.clock.getLastHour()

    const [hourlyReports, sixHourlyReports, dailyReports] = await Promise.all([
      this.aggregatedReportRepository.getAggregateHourly(
        projectIdsFilter,
        getHourlyMinTimestamp(latestTimestamp),
      ),
      this.aggregatedReportRepository.getAggregateSixHourly(
        projectIdsFilter,
        getSixHourlyMinTimestamp(latestTimestamp),
      ),
      this.aggregatedReportRepository.getAggregateDaily(projectIdsFilter),
    ])

    const data: TvlApiCharts = {
      hourly: aggregateRecordsToResponse(hourlyReports),
      sixHourly: aggregateRecordsToResponse(sixHourlyReports),
      daily: aggregateRecordsToResponse(dailyReports),
    }

    return {
      result: 'success',
      data,
    }
  }

  async getAssetTvlApiResponse(
    projectId: ProjectId,
    chainId: ChainId,
    assetId: AssetId,
    assetType: ReportType,
  ): Promise<TokenTvlResult> {
    const asset = this.tokens.find((t) => t.id === assetId)
    const project = this.projects.find((p) => p.projectId === projectId)

    if (!asset || !project) {
      return {
        result: 'error',
        error: 'INVALID_PROJECT_OR_ASSET',
      }
    }

    const latestTimestamp = this.clock.getLastHour()

    const [hourlyReports, sixHourlyReports, dailyReports] = await Promise.all([
      this.reportRepository.getHourly(
        projectId,
        chainId,
        assetId,
        assetType,
        getHourlyMinTimestamp(latestTimestamp),
      ),
      this.reportRepository.getSixHourly(
        projectId,
        chainId,
        assetId,
        assetType,
        getSixHourlyMinTimestamp(latestTimestamp),
      ),
      this.reportRepository.getDaily(projectId, chainId, assetId, assetType),
    ])
    const assetSymbol = asset.symbol.toLowerCase()

    const types: TokenTvlApiChart['types'] = ['timestamp', assetSymbol, 'usd']

    return {
      result: 'success',
      data: {
        hourly: {
          types,
          data: getProjectAssetChartData(hourlyReports, asset.decimals, 1),
        },
        sixHourly: {
          types,
          data: getProjectAssetChartData(sixHourlyReports, asset.decimals, 6),
        },
        daily: {
          types,
          data: getProjectAssetChartData(dailyReports, asset.decimals, 24),
        },
      },
    }
  }

  async getProjectTokenBreakdownApiResponse(): Promise<ProjectAssetBreakdownResult> {
    const latestTimestamp = this.clock.getLastHour()

    const [latestReports, balances, prices] = await Promise.all([
      this.reportRepository.getByTimestamp(latestTimestamp),
      this.balanceRepository.getByTimestamp(latestTimestamp),
      this.priceRepository.getByTimestamp(latestTimestamp),
    ])

    const externalAssetsBreakdown = getNonCanonicalAssetsBreakdown(this.logger)(
      latestReports,
      this.tokens,
      'EBV',
    )

    const nativeAssetsBreakdown = getNonCanonicalAssetsBreakdown(this.logger)(
      latestReports,
      this.tokens,
      'NMV',
    )

    const canonicalAssetsBreakdown = getCanonicalAssetsBreakdown(this.logger)(
      balances,
      prices,
      this.projects,
    )

    const breakdowns = groupAndMergeBreakdowns(this.projects, {
      external: externalAssetsBreakdown,
      native: nativeAssetsBreakdown,
      canonical: canonicalAssetsBreakdown,
    })

    return {
      result: 'success',
      data: {
        dataTimestamp: latestTimestamp,
        breakdowns,
      },
    }
  }
}

export const TYPE_LABELS: TvlApiChart['types'] = [
  'timestamp',
  'valueUsd',
  'cbvUsd',
  'ebvUsd',
  'nmvUsd',
  'valueEth',
  'cbvEth',
  'ebvEth',
  'nmvEth',
]

function aggregateRecordsToResponse(
  hourlyReports: {
    timestamp: UnixTime
    cbvUsdValue: bigint
    cbvEthValue: bigint
    ebvUsdValue: bigint
    ebvEthValue: bigint
    nmvUsdValue: bigint
    nmvEthValue: bigint
    tvlUsdValue: bigint
    tvlEthValue: bigint
  }[],
): TvlApiChart {
  return {
    types: TYPE_LABELS,
    data: hourlyReports.map((report) => [
      report.timestamp,
      asNumber(report.tvlUsdValue, 2),
      asNumber(report.cbvUsdValue, 2),
      asNumber(report.ebvUsdValue, 2),
      asNumber(report.nmvUsdValue, 2),
      asNumber(report.tvlEthValue, 6),
      asNumber(report.cbvEthValue, 6),
      asNumber(report.ebvEthValue, 6),
      asNumber(report.nmvEthValue, 6),
    ]),
  }
}
