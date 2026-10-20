import { redirect } from 'next/navigation'
import * as client from 'openid-client'
import { getOidcConfig } from '@/lib/oidc'
import { clearSession, getSession } from '@/lib/session'

// Ends the app session and the Keycloak SSO session. Clerk's own session is left alone:
// Clerk exposes no end_session endpoint, so the next login may go through Clerk silently.
export async function GET() {
  const session = await getSession()
  await clearSession()

  const config = await getOidcConfig()
  const url = client.buildEndSessionUrl(config, {
    post_logout_redirect_uri: process.env.APP_URL!,
    ...(session && { id_token_hint: session.idToken }),
  })
  redirect(url.href)
}
