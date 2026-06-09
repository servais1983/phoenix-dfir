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
import { apiService, setAuthTokens, setAuthToken, clearAuthToken } from './api'

const instance = axios.create.mock.results[0].value
const requestInterceptor = instance.interceptors.request.use.mock.calls[0][0]
const responseErrorHandler = instance.interceptors.response.use.mock.calls[0][1]

beforeEach(() => {
  localStorage.clear()
  vi.clearAllMocks()
})

describe('gestion des tokens', () => {
  it('setAuthTokens stocke access et refresh', () => {
    setAuthTokens({ access: 'acc-1', refresh: 'ref-1' })
    expect(localStorage.getItem('phoenix_token')).toBe('acc-1')
    expect(localStorage.getItem('phoenix_refresh_token')).toBe('ref-1')
  })

  it('setAuthTokens sans access supprime le token', () => {
    localStorage.setItem('phoenix_token', 'old')
    setAuthTokens({})
    expect(localStorage.getItem('phoenix_token')).toBeNull()
  })

  it('setAuthToken (retro-compat) stocke uniquement l\'access token', () => {
    setAuthToken('acc-legacy')
    expect(localStorage.getItem('phoenix_token')).toBe('acc-legacy')
  })

  it('clearAuthToken purge access, refresh et user', () => {
    localStorage.setItem('phoenix_token', 'a')
    localStorage.setItem('phoenix_refresh_token', 'r')
    localStorage.setItem('phoenix_user', '{}')
    clearAuthToken()
    expect(localStorage.getItem('phoenix_token')).toBeNull()
    expect(localStorage.getItem('phoenix_refresh_token')).toBeNull()
    expect(localStorage.getItem('phoenix_user')).toBeNull()
  })
})

describe('intercepteur de requete', () => {
  it('injecte le header Authorization quand un token existe', () => {
    localStorage.setItem('phoenix_token', 'mon-token')
    const config = requestInterceptor({ headers: {} })
    expect(config.headers.Authorization).toBe('Bearer mon-token')
  })

  it('ne touche pas aux headers sans token', () => {
    const config = requestInterceptor({ headers: {} })
    expect(config.headers.Authorization).toBeUndefined()
  })
})

describe('refresh des tokens', () => {
  it('apiService.refresh stocke la nouvelle paire de tokens', async () => {
    localStorage.setItem('phoenix_refresh_token', 'ref-old')
    axios.post.mockResolvedValueOnce({
      data: { access_token: 'acc-new', refresh_token: 'ref-new' },
    })

    const token = await apiService.refresh()

    expect(token).toBe('acc-new')
    expect(localStorage.getItem('phoenix_token')).toBe('acc-new')
    expect(localStorage.getItem('phoenix_refresh_token')).toBe('ref-new')
    expect(axios.post).toHaveBeenCalledWith(
      expect.stringContaining('/auth/refresh'),
      { refresh_token: 'ref-old' },
      expect.any(Object),
    )
  })

  it('refuse de refresh sans refresh token', async () => {
    await expect(apiService.refresh()).rejects.toThrow('no_refresh_token')
  })

  it('garde l\'ancien refresh token si le serveur n\'en renvoie pas', async () => {
    localStorage.setItem('phoenix_refresh_token', 'ref-keep')
    axios.post.mockResolvedValueOnce({ data: { access_token: 'acc-2' } })

    await apiService.refresh()

    expect(localStorage.getItem('phoenix_refresh_token')).toBe('ref-keep')
  })
})

describe('intercepteur de reponse (401)', () => {
  it('rejoue la requete avec le nouveau token apres un 401', async () => {
    localStorage.setItem('phoenix_refresh_token', 'ref-1')
    axios.post.mockResolvedValueOnce({
      data: { access_token: 'acc-rejoue', refresh_token: 'ref-2' },
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
    localStorage.setItem('phoenix_token', 'acc')
    localStorage.setItem('phoenix_refresh_token', 'ref-mort')
    axios.post.mockRejectedValueOnce(new Error('refresh_failed'))
    const logoutSpy = vi.fn()
    window.addEventListener('auth:logout', logoutSpy)

    const error = {
      config: { url: '/stats', headers: {} },
      response: { status: 401 },
    }
    await expect(responseErrorHandler(error)).rejects.toThrow('refresh_failed')

    expect(localStorage.getItem('phoenix_token')).toBeNull()
    expect(logoutSpy).toHaveBeenCalled()
    window.removeEventListener('auth:logout', logoutSpy)
  })

  it('ne tente pas de refresh sur les endpoints d\'auth', async () => {
    localStorage.setItem('phoenix_refresh_token', 'ref-1')
    const error = {
      config: { url: '/auth/login', headers: {} },
      response: { status: 401 },
    }
    await expect(responseErrorHandler(error)).rejects.toBe(error)
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
    localStorage.setItem('phoenix_refresh_token', 'ref')
    instance.post.mockRejectedValueOnce(new Error('network'))
    await expect(apiService.logout()).resolves.toBeUndefined()
  })

  it('exportStix appelle la bonne route', async () => {
    instance.get.mockResolvedValueOnce({ data: { type: 'bundle' } })
    const data = await apiService.exportStix('inv-42')
    expect(instance.get).toHaveBeenCalledWith('/investigations/inv-42/export/stix')
    expect(data.type).toBe('bundle')
  })
})
