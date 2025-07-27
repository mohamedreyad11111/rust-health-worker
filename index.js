import { Hono } from 'hono'
import { setCookie, getCookie } from 'hono/cookie'
import bcrypt from 'bcryptjs'

const app = new Hono()

app.get('/', c => c.redirect('/login.html'))

app.post('/api/register', async (c) => {
  const body = await c.req.parseBody()
  const email = body.email
  const password = body.password

  if (!email || !password) return c.text('Missing fields', 400)

  const hashed = bcrypt.hashSync(password, 10)
  await c.env.USERS.put(email, hashed)

  return c.text('Registered')
})

app.post('/api/login', async (c) => {
  const body = await c.req.parseBody()
  const email = body.email
  const password = body.password

  const stored = await c.env.USERS.get(email)
  if (!stored) return c.text('Unauthorized', 401)

  const match = bcrypt.compareSync(password, stored)
  if (!match) return c.text('Unauthorized', 401)

  setCookie(c, 'user', email, { httpOnly: true })
  return c.redirect('/admin.html')
})

app.get('/api/logout', (c) => {
  setCookie(c, 'user', '', { maxAge: 0 })
  return c.redirect('/login.html')
})

app.get('/admin.html', async (c) => {
  const user = getCookie(c, 'user')
  if (!user) return c.redirect('/login.html')

  return c.html(`<h1>Welcome, ${user}!</h1><a href="/api/logout">Logout</a>`)
})

export default app
