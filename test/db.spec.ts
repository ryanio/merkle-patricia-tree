import * as tape from 'tape'
import { DB, BatchDBOp } from '../dist/db'

tape('DB basic functionality', (t) => {
  const db = new DB()

  const k = Buffer.from('foo')
  const v = Buffer.from('bar')

  t.test('puts and gets value', async (st) => {
    await db.put(k, v)
    const res = await db.get(k)
    st.ok(v.equals(res!))
    st.end()
  })

  t.test('dels value', async (st) => {
    await db.del(k)
    const res = await db.get(k)
    st.notOk(res)
    st.end()
  })

  t.test('batch ops', async (st) => {
    const k2 = Buffer.from('bar')
    const v2 = Buffer.from('baz')
    const ops = [
      { type: 'put', key: k, value: v },
      { type: 'put', key: k2, value: v2 },
    ] as BatchDBOp[]
    await db.batch(ops)
    const res = await db.get(k2)
    st.ok(v2.equals(res!))
    st.end()
  })
})

tape('DB input types', (t) => {
  const db = new DB()

  t.test('fails for invalid input', async (st) => {
    try {
      const res = await db.get(('test' as unknown) as Buffer)
    } catch (e) {
      st.end()
    }
  })
})
