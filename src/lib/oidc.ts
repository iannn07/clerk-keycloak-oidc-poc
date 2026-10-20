import 'server-only'
import * as client from 'openid-client'

let config: Promise<client.Configuration> | undefined

// Keycloak is the only OIDC provider this app knows about; Keycloak itself brokers to Clerk.
export function getOidcConfig() {
  config ??= client.discovery(
    new URL(process.env.KEYCLOAK_ISSUER!),
    process.env.KEYCLOAK_CLIENT_ID!,
    process.env.KEYCLOAK_CLIENT_SECRET!,
  )
  return config
}

export const redirectUri = `${process.env.APP_URL}/auth/callback`
