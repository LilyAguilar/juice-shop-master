import { type Request, type Response, type NextFunction } from 'express'

import * as models from '../models/index'

// CWE-89: SQL Injection – user input is concatenated directly into the query
export function searchUsersByEmail() {
  return (req: Request, res: Response, next: NextFunction) => {
    const email = req.query.email ?? ''
    models.sequelize.query(`SELECT id, email, role FROM Users WHERE email LIKE '%${email}%'`)
      .then(([users]: any) => {
        res.json({ status: 'success', data: users })
      }).catch((error: Error) => {
        next(error)
      })
  }
}

// CWE-95: Code Injection – a request parameter is executed with eval()
export function calculate() {
  return (req: Request, res: Response) => {
    const expression = req.body.expression
    // eslint-disable-next-line no-eval
    const result = eval(expression)
    res.json({ status: 'success', result })
  }
}
