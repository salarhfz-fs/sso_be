require('dotenv').config()
// built-in modules
const fs = require('fs')
// third-party modules
const Koa = require('koa')
const cors = require('@koa/cors')
const bodyParser = require('koa-bodyparser')
const Router = require('@koa/router')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const DB = require('./db')
const checkAuth = require('./middlewares')
// JWT admin config
const jwt_admin_sign_opts = {
  algorithm: 'RS256',
  expiresIn: 300,
  audience: 'qadev06.deriv.dev',
  issuer: 'qadev06.deriv.dev',
}
const jwt_admin_verify_opts = {
  algorithms: ['RS256'],
  audience: 'qadev06.deriv.dev',
  issuer: 'qadev06.deriv.dev',
}
// JWT users config
const jwt_user_sign_opts = {
  algorithm: 'RS256',
  expiresIn: 3000,
  audience: 'qadev06.deriv.dev',
  issuer: 'qadev06.deriv.dev',
}
const jwt_user_verify_opts = {
  algorithms: ['RS256'],
  audience: 'qadev06.deriv.dev',
  issuer: 'qadev06.deriv.dev',
}


const APP_PORT = parseInt(process.env.APP_PORT)

const app = new Koa()
app.use(cors())
app.context.db = DB
const router = new Router();
// routes
router.post('/users/login', async ctx => {
  const body = ctx.request.body
  const { email, password } = body
  if (email && password) {
    let query = {
      text: 'SELECT * from users WHERE email = $1',
      values: [email.toString().trim()],
    }
    try {
      const result = await ctx.db.query(query)
      if (result.rows.length > 0) {
        const user = result.rows[0]
        const match = await bcrypt.compare(password.toString().trim(), user.password)
        if (match) {
          const token = jwt.sign({ username: user.username }, fs.readFileSync('./keys/user/user_private.key'), jwt_user_sign_opts)
          if (token) {
            ctx.status = 200
            ctx.body = {
              is_error: false,
              code: 200,
              data: {
                token,
              }
            }
          } else {
            ctx.status = 200
            ctx.body = {
              is_error: true,
              code: 500,
              message: 'Internal server error'
            }
          }
        } else {
          ctx.status = 200
          ctx.body = {
            is_error: true,
            code: 401,
            message: 'Invalid email or password'
          }
        }
      } else {
        ctx.status = 200
        ctx.body = {
          is_error: true,
          code: 404,
          message: 'User not found'
        }
      }
    } catch (err) {
      ctx.status = 200
      ctx.body = {
        is_error: true,
        code: 500,
        message: 'Internal server error'
      }
    }
  } else {
    ctx.status = 200
    ctx.body = {
      is_error: true,
      code: 400,
      message: 'Please enter your email and password'
    }
  }
})

router.post('/users/verify', ctx => {
  const body = ctx.request.body
  const { username, token } = body
  if (username && token) {
    try {
      const decoded = token && jwt.verify(token, fs.readFileSync('./keys/user/user_public.key'), jwt_user_verify_opts)
      if (decoded && decoded.username === username) {
        ctx.status = 200
        ctx.body = {
          is_error: false,
          code: 200
        }
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
        message: 'Unauthorized to access the resource'
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
})

router.post('/admins/login', async ctx => {
  const body = ctx.request.body
  const { email, password } = body
  if (email && password) {
    let query = {
      text: 'SELECT * from admins WHERE email = $1',
      values: [email.toString().trim()],
    }
    try {
      const result = await ctx.db.query(query)
      if (result.rows.length > 0) {
        const admin = result.rows[0]
        const match = await bcrypt.compare(password.toString().trim(), admin.password)
        if (match) {
          const token = jwt.sign({ username: admin.username }, fs.readFileSync('./keys/admin/admin_private.key'), jwt_admin_sign_opts)
          if (token) {
            ctx.status = 200
            ctx.body = {
              is_error: false,
              code: 200,
              data: {
                token,
              }
            }
          } else {
            ctx.status = 200
            ctx.body = {
              is_error: true,
              code: 500,
              message: 'Internal server error'
            }
          }
        } else {
          ctx.status = 200
          ctx.body = {
            is_error: true,
            code: 401,
            message: 'Invalid email or password'
          }
        }
      } else {
        ctx.status = 200
        ctx.body = {
          is_error: true,
          code: 404,
          message: 'User not found'
        }
      }
    } catch (err) {
      ctx.status = 200
      ctx.body = {
        is_error: true,
        code: 500,
        message: 'Internal server error'
      }
    }
    const res = DB.query(query)

  } else {
    ctx.status = 200
    ctx.body = {
      is_error: true,
      code: 400,
      message: 'Please enter your email and password'
    }
  }
})

router.get('/admins/users', checkAuth('./keys/admin/admin_public.key', jwt_admin_verify_opts), async ctx => {
  try {
    const query = {
      text: 'SELECT id, username, email, department, is_enabled FROM users WHERE is_deleted = $1 AND is_enabled = $2',
      values: ['f', 't'],
    }
    const result = await ctx.db.query(query)
    if (result.rows.length > 0) {
      ctx.status = 200
      ctx.body = {
        is_error: false,
        code: 200,
        data: result.rows,
      }
    } else {
      ctx.status = 200
      ctx.body = {
        is_error: true,
        code: 404,
        message: 'Not found',
      }
    }
  } catch (err) {
    ctx.status = 200
    ctx.body = {
      is_error: true,
      code: 500,
      message: 'Internal server error'
    }
  }
})

router.post('/admins/users', checkAuth('./keys/admin/admin_public.key', jwt_admin_verify_opts), async ctx => {
  const body = ctx.request.body
  const { username, password, email, department } = body
  if (username && password && email && department) {
    let query = {
      text: 'SELECT id FROM users WHERE email = $1',
      values: [email],
    }
    let result = await ctx.db.query(query)
    if (result.rows.length > 0) {
      ctx.status = 200
      ctx.body = {
        is_error: true,
        code: 409,
        message: 'User already exists'
      }
    } else {
      try {
        const hash_password = await bcrypt.hash(password, parseInt(process.env.SALT_ROUNDS))
        if (hash_password) {
          query = {
            text: 'INSERT INTO users (username, password, email, department) VALUES ($1, $2, $3, $4)',
            values: [username, hash_password, email, department],
          }
          result = await ctx.db.query(query)
          if (result.rowCount === 1) {
            ctx.status = 200
            ctx.body = {
              is_error: false,
              code: 201
            }
          } else {
            ctx.status = 200
            ctx.body = {
              is_error: true,
              code: 500,
              message: 'Internal server error'
            }
          }
        } else {
          ctx.status = 200
          ctx.body = {
            is_error: true,
            code: 500,
            message: 'Internal server error'
          }
        }
      } catch (err) {
        ctx.status = 200
        ctx.body = {
          is_error: true,
          code: 500,
          message: 'Internal server error'
        }
      }
    }
  } else {
    ctx.status = 200
    ctx.body = {
      is_error: true,
      code: 400,
      message: 'Username, password, email and department are required'
    }
  }
})

router.post('/admins/users/update/:id', checkAuth('./keys/admin/admin_public.key', jwt_admin_verify_opts), async ctx => {
  const body = ctx.request.body
  const { username, email, is_enabled = true, department } = body
  if (ctx.params.id && typeof parseInt(ctx.params.id) === 'number' && username?.length && email?.length && department?.length) {
    let query = {
      text: 'SELECT id FROM users WHERE id = $1',
      values: [ctx.params.id],
    }
    let result = await ctx.db.query(query)
    if (result.rows.length > 0) {
      query = {
        text: 'UPDATE users SET username = $1, email = $2, department = $3, is_enabled = $4 WHERE id = $5',
        values: [username, email, department, is_enabled ? 't' : 'f', ctx.params.id],
      }
      result = await ctx.db.query(query)
      if (result.rowCount === 1) {
        ctx.body = {
          is_error: false,
          code: 200
        }
      } else {
        ctx.status = 200
        ctx.body = {
          is_error: true,
          code: 500,
          message: 'Internal server error',
        }
      }
    } else {
      ctx.status = 200
      ctx.body = {
        is_error: true,
        code: 404,
        message: 'User not found'
      }
    }
  } else {
    ctx.status = 200
    ctx.body = {
      is_error: true,
      code: 400,
      message: 'ID, username, email and department are required'
    }
  }
})

router.post('/admins/users/change_password/:id', checkAuth('./keys/admin/admin_public.key', jwt_admin_verify_opts), async ctx => {
  const body = ctx.request.body
  const { password } = body
  if (ctx.params.id && typeof parseInt(ctx.params.id) === 'number' && password?.length === 20) {
    let query = {
      text: 'SELECT id FROM users WHERE id = $1',
      values: [ctx.params.id],
    }
    let result = await ctx.db.query(query)
    if (result.rows.length > 0) {
      try {
        const hash_password = await bcrypt.hash(password, parseInt(process.env.SALT_ROUNDS))
        if (hash_password) {
          query = {
            text: 'UPDATE users SET password = $1 WHERE id = $2',
            values: [hash_password, ctx.params.id],
          }
          result = await ctx.db.query(query)
          if (result.rowCount === 1) {
            ctx.status = 200
            ctx.body = {
              is_error: false,
              code: 200
            }
          } else {
            ctx.status = 200
            ctx.body = {
              is_error: true,
              code: 500,
              message: 'Internal server error',
            }
          }
        } else {
          ctx.status = 200
          ctx.body = {
            is_error: true,
            code: 500,
            message: 'Internal server error',
          }
        }
      } catch (err) {
        ctx.status = 200
        ctx.body = {
          is_error: true,
          code: 500,
          message: 'Internal server error',
        }
      }
    } else {
      ctx.status = 200
      ctx.body = {
        is_error: true,
        code: 404,
        message: 'User not found'
      }
    }
  } else {
    ctx.status = 200
    ctx.body = {
      is_error: true,
      code: 400,
      message: 'ID and password are required'
    }
  }
})

router.delete('/admins/users/:id', checkAuth('./keys/admin/admin_public.key', jwt_admin_verify_opts), async ctx => {
  if (ctx.params.id && typeof parseInt(ctx.params.id) === 'number') {
    let query = {
      text: 'SELECT id FROM users WHERE id = $1',
      values: [ctx.params.id],
    }
    let result = await ctx.db.query(query)
    if (result.rows.length > 0) {
      query = {
        text: 'DELETE FROM users WHERE id = $1',
        values: [ctx.params.id],
      }
      result = await ctx.db.query(query)
      if (result.rowCount === 1) {
        ctx.status = 200
        ctx.body = {
          is_error: false,
          code: 200
        }
      } else {
        ctx.status = 200
        ctx.body = {
          is_error: true,
          code: 500,
          message: 'Internal server error',
        }
      }
    } else {
      ctx.status = 200
      ctx.body = {
        is_error: true,
        code: 404,
        message: 'User not found'
      }
    }
  } else {
    ctx.status = 200
    ctx.body = {
      is_error: true,
      code: 400,
      message: 'ID is required'
    }
  }
})

app
  .use(bodyParser())
  .use(router.routes())
  .use(router.allowedMethods())
  .listen(APP_PORT, () => {
    console.log(`App is running on port ${APP_PORT}`)
  })
