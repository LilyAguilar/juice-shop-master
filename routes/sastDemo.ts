import { type Request, type Response, type NextFunction } from 'express'

import * as models from '../models/index'

// CWE-89 mitigated: user input is passed as a bound replacement, never concatenated into the SQL string
export function searchUsersByEmail() {
  return (req: Request, res: Response, next: NextFunction) => {
    const email = typeof req.query.email === 'string' ? req.query.email : ''
    models.sequelize.query('SELECT id, email, role FROM Users WHERE email LIKE :email', {
      replacements: { email: `%${email}%` }
    })
      .then(([users]: any) => {
        res.json({ status: 'success', data: users })
      }).catch((error: Error) => {
        next(error)
      })
  }
}

// CWE-95 mitigated: the expression is parsed as pure arithmetic instead of being executed with eval()
export function calculate() {
  return (req: Request, res: Response) => {
    const expression = req.body?.expression
    if (typeof expression !== 'string' || expression.length > 100) {
      res.status(400).json({ status: 'error', message: 'Invalid expression' })
      return
    }
    try {
      const result = evaluateArithmetic(expression)
      res.json({ status: 'success', result })
    } catch {
      res.status(400).json({ status: 'error', message: 'Invalid expression' })
    }
  }
}

// Recursive-descent parser supporting only numbers, + - * / and parentheses
function evaluateArithmetic (input: string): number {
  const symbols = input.match(/\d+(?:\.\d+)?|[+\-*/()]|\S/g) ?? []
  let pos = 0

  const parseExpression = (): number => {
    let value = parseTerm()
    while (symbols[pos] === '+' || symbols[pos] === '-') {
      const op = symbols[pos++]
      const rhs = parseTerm()
      value = op === '+' ? value + rhs : value - rhs
    }
    return value
  }

  const parseTerm = (): number => {
    let value = parseFactor()
    while (symbols[pos] === '*' || symbols[pos] === '/') {
      const op = symbols[pos++]
      const rhs = parseFactor()
      value = op === '*' ? value * rhs : value / rhs
    }
    return value
  }

  const parseFactor = (): number => {
    const sym = symbols[pos++]
    if (sym === '-') return -parseFactor()
    if (sym === '(') {
      const value = parseExpression()
      if (symbols[pos++] !== ')') throw new Error('Expected )')
      return value
    }
    if (sym !== undefined && /^\d+(?:\.\d+)?$/.test(sym)) return Number(sym)
    throw new Error('Unexpected symbol')
  }

  const result = parseExpression()
  if (pos !== symbols.length || !Number.isFinite(result)) throw new Error('Invalid expression')
  return result
}
