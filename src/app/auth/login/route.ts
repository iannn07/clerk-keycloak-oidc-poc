import { redirect } from 'next/navigation'
import * as client from 'openid-client'
import { getOidcConfig, redirectUri } from '@/lib/oidc'
import { setLoginTransaction } from '@/lib/session'

export async function GET() {
  const config = await getOidcConfig()
  const codeVerifier = client.randomPKCECodeVerifier()
  const state = client.randomState()
  await setLoginTransaction({ state, codeVerifier })

  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: redirectUri,
    scope: 'openid profile email',
    state,
    code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: 'S256',
    // Skip Keycloak's own login form and go straight to the Clerk identity provider.
    kc_idp_hint: process.env.KEYCLOAK_IDP_HINT!,
  })
  redirect(url.href)
}
