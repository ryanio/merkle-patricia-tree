import { keccak256 } from 'ethereumjs-util'
import { CheckpointTrie } from './checkpointTrie'

/**
 * You can create a secure Trie where the keys are automatically hashed
 * using **keccak256** by using `require('merkle-patricia-tree/secure')`.
 * It has the same methods and constructor as `Trie`.
 * @class SecureTrie
 * @extends Trie
 * @public
 */
export class SecureTrie extends CheckpointTrie {
  constructor(...args: any) {
    super(...args)
  }

  static prove(trie: SecureTrie, key: Buffer): Promise<Buffer[]> {
    const hash = keccak256(key)
    return super.prove(trie, hash)
  }

  static async verifyProof(rootHash: Buffer, key: Buffer, proof: Buffer[]): Promise<Buffer | null> {
    const hash = keccak256(key)
    return super.verifyProof(rootHash, hash, proof)
  }

  copy(): SecureTrie {
    const trie = super.copy(false)
    const db = trie.db.copy()
    return new SecureTrie(db._leveldb, this.root)
  }

  get(key: Buffer): Promise<Buffer | null> {
    return new Promise(async (resolve) => {
      const hash = keccak256(key)
      const value = await super.get(hash)
      resolve(value)
    })
  }

  /**
   * For a falsey value, use the original key
   * to avoid double hashing the key.
   */
  put(key: Buffer, val: Buffer): Promise<void> {
    return new Promise(async (resolve) => {
      if (!val) {
        await this.del(key)
      } else {
        const hash = keccak256(key)
        await super.put(hash, val)
      }
      resolve()
    })
  }

  del(key: Buffer): Promise<void> {
    return new Promise(async (resolve) => {
      const hash = keccak256(key)
      await super.del(hash)
      resolve()
    })
  }
}
