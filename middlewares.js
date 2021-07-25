// built-in modules
const fs = require('fs')
// third-party modules
const jwt = require('jsonwebtoken')

const checkAuth = (pubkey_path, jwt_verify_opts) => async (ctx, next) => {
  if (ctx.request.headers['authorization']) {
    const token = ctx.request.headers['authorization'].split(' ')[1]
    try {
      const decoded = token && jwt.verify(token, fs.readFileSync(pubkey_path), jwt_verify_opts)
      if (decoded) {
        await next()
      } else {
        ctx.status = 200
        ctx.body = {
          is_error: true,
          code: 401,
          message: 'Unauthorized to access the resource'
        }
      }
    } catch (err) {
      ctx.status = 200
      ctx.body = {
        is_error: true,
        code: 401,
        message: 'Unauthorized to access the resource',
      }
    }
  } else {
    ctx.status = 200
    ctx.body = {
      is_error: true,
      code: 401,
      message: 'Unauthorized to access the resource'
    }
  }
}

module.exports = checkAuth
