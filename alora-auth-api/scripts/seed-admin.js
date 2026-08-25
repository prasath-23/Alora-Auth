'use strict'

const argon2 = require('argon2')
const { PrismaClient } = require('@prisma/client')
const prisma = new PrismaClient()

async function run() {
  const client = await prisma.client.findFirst({ where: { domain: 'demo.alora.io' } })
  if (!client) { console.error('Demo client not found — run the db seed first'); process.exit(1) }

  const hash = await argon2.hash('Admin@123', { type: argon2.argon2id })

  const user = await prisma.user.upsert({
    where:  { id: 'seed-admin-demo' },
    update: { password_hash: hash },
    create: {
      id:              'seed-admin-demo',
      client_id:       client.id,
      email:           'admin@demo.alora.io',
      password_hash:   hash,
      account_type:    'EMAIL',
      is_active:       true,
      is_global_admin: true,
    },
  })

  console.log(`Admin inserted: ${user.email}  |  client: ${client.name}  |  id: ${user.id}`)
  await prisma.$disconnect()
}

run().catch(e => { console.error(e); process.exit(1) })
