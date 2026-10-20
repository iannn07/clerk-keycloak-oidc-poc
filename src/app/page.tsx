import { Suspense } from 'react'
import { getSession } from '@/lib/session'

export default function Home() {
  return (
    <main className='mx-auto w-full max-w-3xl p-8 font-sans'>
      <h1 className='text-2xl font-semibold'>Keycloak → Clerk OIDC POC</h1>
      <p className='mt-2 text-sm text-zinc-500'>
        This app only talks to Keycloak. Keycloak brokers the login to Clerk as an OIDC identity provider.
      </p>
      <Suspense fallback={<p className='mt-6'>Loading session…</p>}>
        <SessionPanel />
      </Suspense>
    </main>
  )
}

async function SessionPanel() {
  const session = await getSession()

  if (!session) {
    return (
      <a
        href='/auth/login'
        className='mt-6 inline-block rounded bg-purple-700 px-4 py-2 font-medium text-white'
      >
        Sign in with Clerk (via Keycloak)
      </a>
    )
  }

  const { claims } = session
  return (
    <div className='mt-6 space-y-4'>
      <p>
        Signed in as <strong>{String(claims.email ?? claims.preferred_username)}</strong>
      </p>
      <h2 className='font-semibold'>Keycloak ID token claims</h2>
      <pre className='overflow-x-auto rounded bg-zinc-100 p-4 text-xs dark:bg-zinc-900'>
        {JSON.stringify(claims, null, 2)}
      </pre>
      <a href='/auth/logout' className='inline-block rounded border px-4 py-2'>
        Sign out
      </a>
    </div>
  )
}
