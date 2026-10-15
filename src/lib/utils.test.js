import { describe, it, expect } from 'vitest'
import { cn } from './utils'

describe('cn', () => {
  it('concatene des classes simples', () => {
    expect(cn('a', 'b')).toBe('a b')
  })

  it('ignore les valeurs falsy et les conditions', () => {
    const condition = Number('0') > 0
    expect(cn('a', condition && 'b', undefined, null, 'c')).toBe('a c')
  })

  it('fusionne les classes tailwind en conflit (la derniere gagne)', () => {
    expect(cn('p-2', 'p-4')).toBe('p-4')
    expect(cn('text-red-500', 'text-blue-500')).toBe('text-blue-500')
  })

  it('supporte la syntaxe objet de clsx', () => {
    expect(cn({ a: true, b: false }, 'c')).toBe('a c')
  })
})
