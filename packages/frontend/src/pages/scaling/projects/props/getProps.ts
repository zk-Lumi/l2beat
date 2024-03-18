import { Layer2 } from '@l2beat/config'

import { Config } from '../../../../build/config'
import { getFooterProps, getNavbarProps } from '../../../../components'
import { getChartUrl } from '../../../../scripts/charts/data-controller/ChartDataController'
import { getChart } from '../../../../utils/project/getChart'
import { PagesData, Wrapped } from '../../../Page'
import { ProjectPageProps } from '../view/ProjectPage'
import { getPageMetadata } from './getPageMetadata'
import { getProjectDetails } from './getProjectDetails'
import { getProjectHeader } from './getProjectHeader'

export function getProps(
  project: Layer2,
  config: Config,
  pagesData: PagesData,
): Wrapped<ProjectPageProps> {
  const {
    tvlApiResponse,
    activityApiResponse,
    verificationStatus,
    manuallyVerifiedContracts,
    diffHistory,
    diffState,
  } = pagesData

  const chart = getChart(project, tvlApiResponse, config, activityApiResponse)
  return {
    props: {
      navbar: getNavbarProps(config, 'scaling'),
      projectHeader: getProjectHeader(
        project,
        config,
        tvlApiResponse,
        activityApiResponse,
        diffHistory,
      ),
      projectDetails: getProjectDetails(
        project,
        verificationStatus,
        manuallyVerifiedContracts,
        diffState,
        chart,
      ),
      footer: getFooterProps(config),
    },
    wrapper: {
      preloadApi: getChartUrl(chart.initialType),
      metadata: getPageMetadata(project),
      banner: config.features.banner,
    },
  }
}
