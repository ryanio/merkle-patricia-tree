import * as tape from 'tape'
import { CheckpointTrie } from '../dist'

tape('testing checkpoints', function (tester) {
  const it = tester.test

  let trie: CheckpointTrie
  let trieCopy: CheckpointTrie
  let preRoot: String
  let postRoot: String

  it('setup', async function (t) {
    trie = new CheckpointTrie()
    await trie.put(Buffer.from('do'), Buffer.from('verb'))
    await trie.put(Buffer.from('doge'), Buffer.from('coin'))
    preRoot = trie.root.toString('hex')
    t.end()
  })

  it('should copy trie and get value before checkpoint', async function (t) {
    trieCopy = trie.copy()
    t.equal(trieCopy.root.toString('hex'), preRoot)
    const res = await trieCopy.get(Buffer.from('do'))
    t.ok(Buffer.from('verb').equals(Buffer.from(res!)))
    t.end()
  })

  it('should create a checkpoint', function (t) {
    trie.checkpoint()
    t.end()
  })

  it('should save to the cache', async function (t) {
    await trie.put(Buffer.from('test'), Buffer.from('something'))
    await trie.put(Buffer.from('love'), Buffer.from('emotion'))
    postRoot = trie.root.toString('hex')
    t.end()
  })

  it('should get values from before checkpoint', async function (t) {
    const res = await trie.get(Buffer.from('doge'))
    t.ok(Buffer.from('coin').equals(Buffer.from(res!)))
    t.end()
  })

  it('should get values from cache', async function (t) {
    const res = await trie.get(Buffer.from('love'))
    t.ok(Buffer.from('emotion').equals(Buffer.from(res!)))
    t.end()
  })

  it('should copy trie and get upstream and cache values after checkpoint', async function (t) {
    trieCopy = trie.copy()
    t.equal(trieCopy.root.toString('hex'), postRoot)
    t.equal(trieCopy._checkpoints.length, 1)
    t.ok(trieCopy.isCheckpoint)
    const res = await trieCopy.get(Buffer.from('do'))
    t.ok(Buffer.from('verb').equals(Buffer.from(res!)))
    const res2 = await trieCopy.get(Buffer.from('love'))
    t.ok(Buffer.from('emotion').equals(Buffer.from(res2!)))
    t.end()
  })

  it('should revert to the orginal root', async function (t) {
    t.equal(trie.isCheckpoint, true)
    await trie.revert()
    t.equal(trie.root.toString('hex'), preRoot)
    t.equal(trie.isCheckpoint, false)
    t.end()
  })

  it('should not get values from cache after revert', async function (t) {
    const res = await trie.get(Buffer.from('love'))
    t.notOk(res)
    t.end()
  })

  it('should commit a checkpoint', async function (t) {
    trie.checkpoint()
    await trie.put(Buffer.from('test'), Buffer.from('something'))
    await trie.put(Buffer.from('love'), Buffer.from('emotion'))
    await trie.commit()
    t.equal(trie.isCheckpoint, false)
    t.equal(trie.root.toString('hex'), postRoot)
    t.end()
  })

  it('should get new values after commit', async function (t) {
    const res = await trie.get(Buffer.from('love'))
    t.ok(Buffer.from('emotion').equals(Buffer.from(res!)))
    t.end()
  })

  it('should commit a nested checkpoint', async function (t) {
    trie.checkpoint()
    let root: Buffer
    await trie.put(Buffer.from('test'), Buffer.from('something else'))
    root = trie.root
    trie.checkpoint()
    await trie.put(Buffer.from('the feels'), Buffer.from('emotion'))
    await trie.revert()
    await trie.commit()
    t.equal(trie.isCheckpoint, false)
    t.equal(trie.root.toString('hex'), root.toString('hex'))
    t.end()
  })
})
