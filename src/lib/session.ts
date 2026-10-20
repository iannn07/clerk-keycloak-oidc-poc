import 'server-only'
import { cookies } from 'next/headers'
import { sealData, unsealData } from 'iron-session'

export type Session = {
  claims: Record<string, unknown>
  idToken: string
}

// Short-lived state for a single login round trip (state + PKCE verifier).
export type LoginTransaction = {
  state: string
  codeVerifier: string
}

const SESSION_COOKIE = 'poc_session'
const TX_COOKIE = 'poc_login_tx'
const password = process.env.SESSION_PASSWORD!
const cookieOptions = {
  httpOnly: true,
  sameSite: 'lax' as const,
  secure: process.env.NODE_ENV === 'production',
  path: '/',
}

async function read<T>(name: string): Promise<T | undefined> {
  const value = (await cookies()).get(name)?.value
  if (!value) return undefined
  const data = await unsealData<T>(value, { password })
  // unsealData returns {} for an expired or tampered seal
  return Object.keys(data as object).length ? data : undefined
}

async function write(name: string, data: object, ttl: number) {
  const sealed = await sealData(data, { password, ttl })
  ;(await cookies()).set(name, sealed, { ...cookieOptions, maxAge: ttl })
}

export const getSession = () => read<Session>(SESSION_COOKIE)
export const setSession = (session: Session) => write(SESSION_COOKIE, session, 60 * 60 * 8)
export const clearSession = async () => (await cookies()).delete(SESSION_COOKIE)

export const getLoginTransaction = () => read<LoginTransaction>(TX_COOKIE)
export const setLoginTransaction = (tx: LoginTransaction) => write(TX_COOKIE, tx, 60 * 10)
export const clearLoginTransaction = async () => (await cookies()).delete(TX_COOKIE)
