import { Trie as BaseTrie } from './baseTrie'
import { ScratchReadStream } from './scratchReadStream'
import { ScratchDB } from './scratch'
import { DB, BatchDBOp } from './db'
import { TrieNode } from './trieNode'
const WriteStream = require('level-ws')

export class CheckpointTrie extends BaseTrie {
  _mainDB: DB
  _scratch: ScratchDB | null
  _checkpoints: Buffer[]

  constructor(...args: any) {
    super(...args)
    // Reference to main DB instance
    this._mainDB = this.db
    // DB instance used for checkpoints
    this._scratch = null
    // Roots of trie at the moment of checkpoint
    this._checkpoints = []
  }

  /**
   * Is the trie during a checkpoint phase?
   */
  get isCheckpoint() {
    return this._checkpoints.length > 0
  }

  /**
   * Creates a checkpoint that can later be reverted to or committed.
   * After this is called, no changes to the trie will be permanently saved
   * until `commit` is called. Calling `putRaw` overrides the checkpointing
   * mechanism and would directly write to db.
   */
  checkpoint() {
    const wasCheckpoint = this.isCheckpoint
    this._checkpoints.push(this.root)

    // Entering checkpoint mode is not necessary for nested checkpoints
    if (!wasCheckpoint && this.isCheckpoint) {
      this._enterCpMode()
    }
  }

  /**
   * Commits a checkpoint to disk, if current checkpoint is not nested. If
   * nested, only sets the parent checkpoint as current checkpoint.
   * @method commit
   * @returns {Promise}
   * @throws If not during a checkpoint phase
   */
  commit(): Promise<void> {
    return new Promise(async (resolve, reject) => {
      await this.lock.wait()
      if (!this.isCheckpoint) {
        reject(new Error('trying to commit when not checkpointed'))
      }

      this._checkpoints.pop()

      if (!this.isCheckpoint) {
        await this._exitCpMode(true)
      }
      await this.lock.signal()
      resolve()
    })
  }

  /**
   * Reverts the trie to the state it was at when `checkpoint` was first called.
   * If during a nested checkpoint, sets root to most recent checkpoint, and sets
   * parent checkpoint as current.
   */
  revert(): Promise<void> {
    return new Promise(async (resolve) => {
      await this.lock.wait()
      if (this.isCheckpoint) {
        this.root = this._checkpoints.pop()!
        if (!this.isCheckpoint) {
          await this._exitCpMode(false)
          resolve()
        }
      }
      this.lock.signal()
      resolve()
    })
  }

  /**
   * Returns a copy of the underlying trie with the interface
   * of CheckpointTrie. If during a checkpoint, the copy will
   * contain the checkpointing metadata (incl. reference to the same scratch).
   * @param {boolean} includeCheckpoints - If true and during a checkpoint, the copy will
   * contain the checkpointing metadata and will use the same scratch as underlying db.
   */
  copy(includeCheckpoints: boolean = true): CheckpointTrie {
    const db = this._mainDB.copy()
    const trie = new CheckpointTrie(db._leveldb, this.root)
    if (includeCheckpoints && this.isCheckpoint) {
      trie._checkpoints = this._checkpoints.slice()
      trie._scratch = this._scratch!.copy()
      trie.db = trie._scratch
    }
    return trie
  }

  /**
   * Enter into checkpoint mode.
   * @private
   */
  _enterCpMode() {
    this._scratch = new ScratchDB(this._mainDB)
    this.db = this._scratch
  }

  /**
   * Exit from checkpoint mode.
   * @private
   */
  async _exitCpMode(commitState: boolean): Promise<void> {
    return new Promise(async (resolve) => {
      const scratch = this._scratch as ScratchDB
      this._scratch = null
      this.db = this._mainDB

      if (commitState) {
        this._createScratchReadStream(scratch)
          .pipe(WriteStream(this.db._leveldb))
          .on('close', resolve)
      } else {
        process.nextTick(resolve)
      }
    })
  }

  /**
   * Returns a `ScratchReadStream` based on the state updates
   * since checkpoint.
   * @method createScratchReadStream
   * @private
   */
  _createScratchReadStream(scratch: ScratchDB) {
    scratch = scratch || this._scratch
    const trie = new BaseTrie(scratch._leveldb, this.root)
    trie.db = scratch
    return new ScratchReadStream(trie)
  }

  // formats node to be saved by levelup.batch.
  // returns either the hash that will be used key or the rawNode
  _formatNode(node: TrieNode, topLevel: boolean, opStack: BatchDBOp[], remove: boolean = false) {
    const rlpNode = node.serialize()

    if (rlpNode.length >= 32 || topLevel) {
      const hashRoot = node.hash()

      if (remove && this.isCheckpoint) {
        opStack.push({
          type: 'del',
          key: hashRoot,
        })
      } else {
        opStack.push({
          type: 'put',
          key: hashRoot,
          value: rlpNode,
        })
      }

      return hashRoot
    }

    return node.raw()
  }
}
