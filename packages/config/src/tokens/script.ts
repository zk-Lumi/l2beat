import { assert } from '@l2beat/backend-tools'
import {
  AssetId,
  ChainId,
  CoingeckoId,
  EthereumAddress,
  numberAs,
  stringAs,
  UnixTime,
} from '@l2beat/shared-pure'
import { readFileSync } from 'fs'
import { z } from 'zod'

import { Output } from './types'

export type OldToken = z.infer<typeof OldToken>
export const OldToken = z.object({
  id: stringAs((s) => AssetId(s)),
  name: z.string(),
  coingeckoId: stringAs((s) => CoingeckoId(s)),
  address: stringAs((s) => EthereumAddress(s)).optional(),
  symbol: z.string(),
  decimals: z.number(),
  sinceTimestamp: numberAs((n) => new UnixTime(n)),
  /** @deprecated */
  category: z.enum(['ether', 'stablecoin', 'other']),
  iconUrl: z.optional(z.string()),
  chainId: numberAs(ChainId),
  type: z.enum(['CBV', 'EBV', 'NMV']),
  formula: z.enum(['totalSupply', 'locked', 'circulatingSupply']),
  bridgedUsing: z.optional(
    z.object({
      bridge: z.string(),
      slug: z.string().optional(),
    }),
  ),
})

export type OldOutput = z.infer<typeof OldOutput>
export const OldOutput = z.object({
  comment: z.string().optional(),
  tokens: z.array(OldToken),
})

const GENERATED_FILE = './src/tokens/generated.json'
const OLD_FILE = './src/tokens/old.json'

function main() {
  const generatedFile = readFileSync(GENERATED_FILE, 'utf-8')
  const generated = Output.parse(JSON.parse(generatedFile))

  const oldFile = readFileSync(OLD_FILE, 'utf-8')
  const old = OldOutput.parse(JSON.parse(oldFile))

  console.log('\nAdded tokens:\n')
  for (const g of generated.tokens) {
    const id = old.tokens.find(
      (o) => o.symbol === g.symbol && o.chainId === g.chainId,
    )
    if (!id) {
      console.log(g.id.toString())
    }
  }

  assert(
    generated.tokens.length === old.tokens.length + 1, // +1 because of the added token
    'Length mismatch' +
      generated.tokens.length.toString() +
      ' ' +
      old.tokens.length.toString(),
  )

  console.log('\nNew token ids:\n')
  for (const g of generated.tokens) {
    const id = old.tokens.find((o) => o.id === g.id)
    if (!id) {
      console.log(g.id.toString())
    }
  }

  console.log('\nSince timestamp changes:\n')
  for (const o of old.tokens) {
    const sinceTimestamp = o.sinceTimestamp.toNumber()

    const g = generated.tokens.find(
      (g) => o.symbol === g.symbol && o.chainId === g.chainId,
    )

    assert(g, 'Token not found')

    const gSinceTimestamp = Math.max(
      g.deploymentTimestamp.toNumber(),
      g.coingeckoListingTimestamp.toNumber(),
    )

    const daysDiff = Math.floor(
      (gSinceTimestamp - sinceTimestamp) / 60 / 60 / 24,
    )

    if (daysDiff > 0) {
      console.log(`${g.id.toString()} ${daysDiff} days`)
    }
  }
}

main()
