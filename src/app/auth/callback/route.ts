import { redirect } from 'next/navigation'
import * as client from 'openid-client'
import { getOidcConfig, redirectUri } from '@/lib/oidc'
import { clearLoginTransaction, getLoginTransaction, setSession } from '@/lib/session'

export async function GET(request: Request) {
  const tx = await getLoginTransaction()
  if (!tx) {
    return new Response('Login transaction missing or expired. Start again at /auth/login.', { status: 400 })
  }

  const config = await getOidcConfig()
  // Rebuild the URL against APP_URL so the redirect_uri matches what Keycloak saw.
  const currentUrl = new URL(redirectUri)
  currentUrl.search = new URL(request.url).search

  const tokens = await client.authorizationCodeGrant(config, currentUrl, {
    expectedState: tx.state,
    pkceCodeVerifier: tx.codeVerifier,
  })

  await clearLoginTransaction()
  await setSession({ claims: { ...tokens.claims() }, idToken: tokens.id_token! })
  redirect('/')
}
