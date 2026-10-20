import 'server-only'
import * as client from 'openid-client'

let config: Promise<client.Configuration> | undefined

// Keycloak is the only OIDC provider this app knows about; Keycloak itself brokers to Clerk.
export function getOidcConfig() {
  const issuer = new URL(process.env.KEYCLOAK_ISSUER!)
  config ??= client.discovery(
    issuer,
    process.env.KEYCLOAK_CLIENT_ID!,
    process.env.KEYCLOAK_CLIENT_SECRET!,
    undefined,
    // The local docker Keycloak serves plain HTTP; an https issuer never gets this.
    issuer.protocol === 'http:' ? { execute: [client.allowInsecureRequests] } : undefined,
  )
  return config
}

export const redirectUri = `${process.env.APP_URL}/auth/callback`
