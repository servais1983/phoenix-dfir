import { describe, it, expect, vi, beforeEach } from 'vitest'

// Mock axios : l'instance creee par axios.create doit etre appelable
// (l'intercepteur de reponse rejoue la requete via api(originalRequest))
vi.mock('axios', () => {
  const instance = Object.assign(vi.fn(), {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
  })
  return {
    default: {
      create: vi.fn(() => instance),
      post: vi.fn(),
      get: vi.fn(),
    },
  }
})

import axios from 'axios'
import { apiService, setAuthTokens, setAuthToken, clearAuthToken, getAccessToken } from './api'

const instance = axios.create.mock.results[0].value
const createConfig = axios.create.mock.calls[0][0]
const requestInterceptor = instance.interceptors.request.use.mock.calls[0][0]
const responseErrorHandler = instance.interceptors.response.use.mock.calls[0][1]

beforeEach(() => {
  localStorage.clear()
  clearAuthToken()
  vi.clearAllMocks()
})

describe('gestion des tokens (memoire uniquement)', () => {
  it('envoie les cookies (refresh HttpOnly) avec les requetes', () => {
    expect(createConfig.withCredentials).toBe(true)
  })

  it('setAuthTokens garde l\'access token en memoire, jamais dans localStorage', () => {
    setAuthTokens({ access: 'acc-1', refresh: 'ref-1' })
    expect(getAccessToken()).toBe('acc-1')
    expect(localStorage.getItem('phoenix_token')).toBeNull()
    expect(localStorage.getItem('phoenix_refresh_token')).toBeNull()
  })

  it('setAuthTokens sans access supprime le token', () => {
    setAuthTokens({ access: 'old' })
    setAuthTokens({})
    expect(getAccessToken()).toBeNull()
  })

  it('setAuthToken (retro-compat) stocke uniquement l\'access token', () => {
    setAuthToken('acc-legacy')
    expect(getAccessToken()).toBe('acc-legacy')
    expect(localStorage.getItem('phoenix_token')).toBeNull()
  })

  it('clearAuthToken vide la memoire et purge les anciennes cles localStorage', () => {
    setAuthTokens({ access: 'a' })
    localStorage.setItem('phoenix_token', 'a')
    localStorage.setItem('phoenix_refresh_token', 'r')
    localStorage.setItem('phoenix_user', '{}')
    clearAuthToken()
    expect(getAccessToken()).toBeNull()
    expect(localStorage.getItem('phoenix_token')).toBeNull()
    expect(localStorage.getItem('phoenix_refresh_token')).toBeNull()
    expect(localStorage.getItem('phoenix_user')).toBeNull()
  })
})

describe('intercepteur de requete', () => {
  it('injecte le header Authorization quand un token existe', () => {
    setAuthTokens({ access: 'mon-token' })
    const config = requestInterceptor({ headers: {} })
    expect(config.headers.Authorization).toBe('Bearer mon-token')
  })

  it('ignore un ancien token reste dans localStorage', () => {
    localStorage.setItem('phoenix_token', 'vieux-token')
    const config = requestInterceptor({ headers: {} })
    expect(config.headers.Authorization).toBeUndefined()
  })

  it('ne touche pas aux headers sans token', () => {
    const config = requestInterceptor({ headers: {} })
    expect(config.headers.Authorization).toBeUndefined()
  })
})

describe('refresh des tokens (cookie HttpOnly)', () => {
  it('apiService.refresh utilise le cookie (aucun refresh token dans le corps)', async () => {
    axios.post.mockResolvedValueOnce({
      data: { access_token: 'acc-new', user: { id: 1, username: 'a' } },
    })

    const token = await apiService.refresh()

    expect(token).toBe('acc-new')
    expect(getAccessToken()).toBe('acc-new')
    expect(localStorage.getItem('phoenix_token')).toBeNull()
    expect(axios.post).toHaveBeenCalledWith(
      expect.stringContaining('/auth/refresh'),
      null,
      expect.objectContaining({ withCredentials: true }),
    )
  })

  it('restoreSession renvoie l\'utilisateur de la session restauree', async () => {
    axios.post.mockResolvedValueOnce({
      data: { access_token: 'acc-r', user: { id: 7, username: 'restaure' } },
    })
    const data = await apiService.restoreSession()
    expect(data.user.username).toBe('restaure')
    expect(getAccessToken()).toBe('acc-r')
  })

  it('echoue si le serveur refuse le cookie', async () => {
    axios.post.mockRejectedValueOnce(new Error('401'))
    await expect(apiService.refresh()).rejects.toThrow('401')
    expect(getAccessToken()).toBeNull()
  })

  it('deduplique les refresh concurrents (rotation a usage unique)', async () => {
    axios.post.mockResolvedValueOnce({ data: { access_token: 'acc-once' } })
    const [a, b] = await Promise.all([apiService.refresh(), apiService.refresh()])
    expect(a).toBe('acc-once')
    expect(b).toBe('acc-once')
    expect(axios.post).toHaveBeenCalledTimes(1)
  })
})

describe('intercepteur de reponse (401)', () => {
  it('rejoue la requete avec le nouveau token apres un 401', async () => {
    axios.post.mockResolvedValueOnce({
      data: { access_token: 'acc-rejoue' },
    })
    instance.mockResolvedValueOnce({ data: { ok: true } })

    const error = {
      config: { url: '/investigations', headers: {} },
      response: { status: 401 },
    }
    const result = await responseErrorHandler(error)

    expect(result.data.ok).toBe(true)
    expect(instance).toHaveBeenCalledWith(
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: 'Bearer acc-rejoue' }),
        _retried: true,
      }),
    )
  })

  it('deconnecte (auth:logout) quand le refresh echoue', async () => {
    setAuthTokens({ access: 'acc' })
    axios.post.mockRejectedValueOnce(new Error('refresh_failed'))
    const logoutSpy = vi.fn()
    window.addEventListener('auth:logout', logoutSpy)

    const error = {
      config: { url: '/stats', headers: {} },
      response: { status: 401 },
    }
    await expect(responseErrorHandler(error)).rejects.toThrow('refresh_failed')

    expect(getAccessToken()).toBeNull()
    expect(logoutSpy).toHaveBeenCalled()
    window.removeEventListener('auth:logout', logoutSpy)
  })

  it('ne tente pas de refresh sur les endpoints d\'auth', async () => {
    for (const url of ['/auth/login', '/auth/password', '/auth/logout']) {
      const error = {
        config: { url, headers: {} },
        response: { status: 401 },
      }
      await expect(responseErrorHandler(error)).rejects.toBe(error)
    }
    expect(axios.post).not.toHaveBeenCalled()
  })

  it('propage les erreurs non-401 sans refresh', async () => {
    const error = {
      config: { url: '/stats', headers: {} },
      response: { status: 500, data: { error: 'boom' } },
    }
    await expect(responseErrorHandler(error)).rejects.toBe(error)
    expect(axios.post).not.toHaveBeenCalled()
  })
})

describe('apiService', () => {
  it('login poste les identifiants sur /auth/login', async () => {
    instance.post.mockResolvedValueOnce({ data: { access_token: 'a' } })
    const data = await apiService.login('analyste', 'S3cret!Passw0rd')
    expect(instance.post).toHaveBeenCalledWith('/auth/login', {
      username: 'analyste',
      password: 'S3cret!Passw0rd',
    })
    expect(data.access_token).toBe('a')
  })

  it('getInvestigations pagine correctement', async () => {
    instance.get.mockResolvedValueOnce({ data: { items: [], total: 0 } })
    await apiService.getInvestigations(2, 25)
    expect(instance.get).toHaveBeenCalledWith('/investigations?page=2&per_page=25')
  })

  it('logout reste silencieux si l\'API echoue', async () => {
    instance.post.mockRejectedValueOnce(new Error('network'))
    await expect(apiService.logout()).resolves.toBeUndefined()
  })

  it('logout n\'envoie aucun refresh token (le cookie HttpOnly suffit)', async () => {
    instance.post.mockResolvedValueOnce({ data: {} })
    await apiService.logout()
    expect(instance.post).toHaveBeenCalledWith('/auth/logout')
  })

  it('register transmet le jeton d\'installation', async () => {
    instance.post.mockResolvedValueOnce({ data: { access_token: 'a' } })
    await apiService.register('admin', 'S3cret!Passw0rd', 'Admin', 'setup-xyz')
    expect(instance.post).toHaveBeenCalledWith('/auth/register', {
      username: 'admin', password: 'S3cret!Passw0rd', display_name: 'Admin', setup_token: 'setup-xyz',
    })
  })

  it('getSetupStatus interroge le statut d\'installation', async () => {
    instance.get.mockResolvedValueOnce({ data: { needs_setup: true, registration_open: false } })
    const data = await apiService.getSetupStatus()
    expect(instance.get).toHaveBeenCalledWith('/auth/setup-status')
    expect(data.needs_setup).toBe(true)
  })

  it('gere les membres d\'une enquete', async () => {
    instance.post.mockResolvedValueOnce({ data: { items: [] } })
    await apiService.addInvestigationMember('inv-1', 'bob')
    expect(instance.post).toHaveBeenCalledWith('/investigations/inv-1/members', { username: 'bob' })
    instance.delete.mockResolvedValueOnce({ data: { items: [] } })
    await apiService.removeInvestigationMember('inv-1', 4)
    expect(instance.delete).toHaveBeenCalledWith('/investigations/inv-1/members/4')
  })

  it('administration : role d\'un utilisateur', async () => {
    instance.put.mockResolvedValueOnce({ data: { id: 3, role: 'viewer' } })
    await apiService.setUserRole(3, 'viewer')
    expect(instance.put).toHaveBeenCalledWith('/auth/users/3/role', { role: 'viewer' })
  })

  it('exportStix appelle la bonne route', async () => {
    instance.get.mockResolvedValueOnce({ data: { type: 'bundle' } })
    const data = await apiService.exportStix('inv-42')
    expect(instance.get).toHaveBeenCalledWith('/investigations/inv-42/export/stix')
    expect(data.type).toBe('bundle')
  })
})

describe('apiService console enqueteur DFIR', () => {
  it('getCustody filtre par enquete', async () => {
    instance.get.mockResolvedValueOnce({ data: { items: [], total: 0 } })
    await apiService.getCustody('inv-7', 100)
    expect(instance.get).toHaveBeenCalledWith('/custody', { params: { limit: 100, investigation_id: 'inv-7' } })
  })

  it('verifyCustody interroge la verification de la chaine', async () => {
    instance.get.mockResolvedValueOnce({ data: { valid: true, entries: 3 } })
    const data = await apiService.verifyCustody()
    expect(instance.get).toHaveBeenCalledWith('/custody/verify')
    expect(data.valid).toBe(true)
  })

  it('decideRemediation poste la decision et la note', async () => {
    instance.post.mockResolvedValueOnce({ data: { id: 'ACT-1', status: 'APPROVED' } })
    const data = await apiService.decideRemediation('ACT-1', 'approve', 'ok CERT')
    expect(instance.post).toHaveBeenCalledWith('/remediation/ACT-1/decision', { decision: 'approve', note: 'ok CERT' })
    expect(data.status).toBe('APPROVED')
  })

  it('importFromVault allonge le delai pour les gros dumps', async () => {
    instance.post.mockResolvedValueOnce({ data: { imported: [], rejected: [] } })
    await apiService.importFromVault('inv-1', ['host1/memdump.raw'])
    const [url, body, config] = instance.post.mock.calls[0]
    expect(url).toBe('/evidence-vault/import')
    expect(body).toEqual({ investigation_id: 'inv-1', paths: ['host1/memdump.raw'] })
    expect(config.timeout).toBeGreaterThan(60000)
  })
})
