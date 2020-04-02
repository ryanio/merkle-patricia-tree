import { LevelUp } from 'levelup'
import Semaphore from 'semaphore-async-await'
import { toBuffer, keccak, KECCAK256_RLP } from 'ethereumjs-util'
import { DB, BatchDBOp, PutBatch } from './db'
import { TrieReadStream as ReadStream } from './readStream'
import { PrioritizedTaskExecutor } from './prioritizedTaskExecutor'
import { stringToNibbles, matchingNibbleLength, doKeysMatch } from './util/nibbles'
import {
  TrieNode,
  decodeNode,
  decodeRawNode,
  isRawNode,
  BranchNode,
  ExtensionNode,
  LeafNode,
  EmbeddedNode,
} from './trieNode'
const assert = require('assert')

interface Path {
  node: TrieNode
  remaining: number[]
  stack: TrieNode[]
}

type FoundNode = (nodeRef: Buffer, node: TrieNode, key: number[], walkController: any) => void

/**
 * Use `require('merkel-patricia-tree').BaseTrie` for the base interface. In Ethereum applications
 * stick with the Secure Trie Overlay `require('merkel-patricia-tree').SecureTrie`.
 * The API for the raw and the secure interface are about the same.
 * @param {Object} [db] A [levelup](https://github.com/Level/levelup) instance. By default creates an in-memory [memdown](https://github.com/Level/memdown) instance.
 * If the db is `null` or left undefined, then the trie will be stored in memory via [memdown](https://github.com/Level/memdown)
 * @param {Buffer|String} [root] A hex `String` or `Buffer` for the root of a previously stored trie
 * @prop {Buffer} root The current root of the `trie`
 * @prop {Buffer} EMPTY_TRIE_ROOT the Root for an empty trie
 */
export class Trie {
  EMPTY_TRIE_ROOT: Buffer
  db: DB
  protected lock: Semaphore
  private _root: Buffer

  constructor(db?: LevelUp | null, root?: Buffer) {
    this.EMPTY_TRIE_ROOT = KECCAK256_RLP
    this.lock = new Semaphore(1)
    this.db = db ? new DB(db) : new DB()
    this._root = this.EMPTY_TRIE_ROOT
    if (root) {
      this.setRoot(root)
    }
  }

  static async fromProof(proofNodes: Buffer[], proofTrie?: Trie): Promise<Trie> {
    let opStack = proofNodes.map((nodeValue) => {
      return {
        type: 'put',
        key: keccak(nodeValue),
        value: toBuffer(nodeValue),
      } as PutBatch
    })

    if (!proofTrie) {
      proofTrie = new Trie()
      if (opStack[0]) {
        proofTrie.root = opStack[0].key
      }
    }

    await proofTrie.db.batch(opStack)
    return proofTrie
  }

  static async prove(trie: Trie, key: Buffer): Promise<Buffer[]> {
    return new Promise(async (resolve) => {
      const path = await trie.findPath(key)
      const p = path.stack.map((stackElem) => {
        return stackElem.serialize()
      })
      resolve(p)
    })
  }

  static async verifyProof(
    rootHash: Buffer,
    key: Buffer,
    proofNodes: Buffer[],
  ): Promise<Buffer | null> {
    let proofTrie = new Trie(null, rootHash)
    try {
      proofTrie = await Trie.fromProof(proofNodes, proofTrie)
    } catch (e) {
      throw new Error('Invalid proof nodes given')
    }
    return proofTrie.get(key)
  }

  set root(value: Buffer) {
    this.setRoot(value)
  }

  get root(): Buffer {
    return this._root
  }

  setRoot(value?: Buffer) {
    if (value) {
      value = toBuffer(value)
      assert(value.length === 32, 'Invalid root length. Roots are 32 bytes')
    } else {
      value = this.EMPTY_TRIE_ROOT
    }

    this._root = value
  }

  /**
   * Gets a value given a `key`
   * @method get
   * @memberof Trie
   * @param {Buffer} key - the key to search for
   * @returns {Promise} - Returns a promise that resolves to `Buffer` if a value was found or `null` if no value was found.
   */
  async get(key: Buffer): Promise<Buffer | null> {
    return new Promise(async (resolve) => {
      key = toBuffer(key)

      const path = await this.findPath(key)

      let value = null
      if (path.node && path.remaining.length === 0) {
        value = path.node.value
      }

      resolve(value)
    })
  }

  /**
   * Stores a given `value` at the given `key`
   * @method put
   * @memberof Trie
   * @param {Buffer} key
   * @param {Buffer} Value
   * @returns {Promise}
   */
  put(key: Buffer, value: Buffer): Promise<void> {
    return new Promise(async (resolve) => {
      key = toBuffer(key)
      value = toBuffer(value)

      if (!value || value.toString() === '') {
        await this.del(key)
      } else {
        await this.lock.wait()
        if (this.root.toString('hex') !== KECCAK256_RLP.toString('hex')) {
          // first try to find the give key or its nearst node
          const path = await this.findPath(key)
          // then update
          await this._updateNode(key, value, path.remaining, path.stack)
        } else {
          await this._createInitialNode(key, value) // if no root initialize this trie
        }
        this.lock.signal()
      }
      resolve()
    })
  }

  /**
   * deletes a value given a `key`
   * @method del
   * @memberof Trie
   * @param {Buffer} key
   * @returns {Promise}
   */
  del(key: Buffer): Promise<void> {
    return new Promise(async (resolve) => {
      key = toBuffer(key)

      await this.lock.wait()
      const path = await this.findPath(key)
      if (path.node) {
        await this._deleteNode(key, path.stack)
      }
      this.lock.signal()

      resolve()
    })
  }

  // retrieves a node from dbs by hash
  async _lookupNode(node: Buffer | Buffer[]): Promise<TrieNode | null> {
    return new Promise(async (resolve, reject) => {
      if (isRawNode(node)) {
        resolve(decodeRawNode(node as Buffer[]))
      } else {
        const value = await this.db.get(node as Buffer)
        let foundNode = null
        if (value) {
          foundNode = decodeNode(value)
        } else {
          reject(new Error('Missing node in DB'))
        }
        resolve(foundNode)
      }
    })
  }

  // writes a single node to dbs
  _putNode(node: TrieNode): Promise<void> {
    return new Promise(async (resolve) => {
      const hash = node.hash()
      const serialized = node.serialize()
      await this.db.put(hash, serialized)
      resolve()
    })
  }

  /**
   * Tries to find a path to the node for the given key
   * It returns a `stack` of nodes to the closet node
   * @method findPath
   * @memberof Trie
   * @param {String|Buffer} key - the search key
   * @returns {Promise} - Returns promise resolving to interface Path
   */
  async findPath(key: Buffer): Promise<Path> {
    return new Promise(async (resolve) => {
      const stack: TrieNode[] = []
      let targetKey = stringToNibbles(key)

      await this._walkTrie(this.root, processNode)
      resolve()

      function processNode(
        nodeRef: Buffer,
        node: TrieNode,
        keyProgress: number[],
        walkController: any,
      ) {
        const keyRemainder = targetKey.slice(matchingNibbleLength(keyProgress, targetKey))
        stack.push(node)

        if (node instanceof BranchNode) {
          if (keyRemainder.length === 0) {
            walkController.return(null, node, [], stack)
            // we exhausted the key without finding a node
          } else {
            const branchIndex = keyRemainder[0]
            const branchNode = node.getBranch(branchIndex)
            if (!branchNode) {
              // there are no more nodes to find and we didn't find the key
              walkController.return(null, null, keyRemainder, stack)
            } else {
              // node found, continuing search
              walkController.only(branchIndex)
            }
          }
        } else if (node instanceof LeafNode) {
          if (doKeysMatch(keyRemainder, node.key)) {
            // keys match, return node with empty key
            walkController.return(null, node, [], stack)
          } else {
            // reached leaf but keys dont match
            walkController.return(null, null, keyRemainder, stack)
          }
        } else if (node instanceof ExtensionNode) {
          const matchingLen = matchingNibbleLength(keyRemainder, node.key)
          if (matchingLen !== node.key.length) {
            // keys dont match, fail
            walkController.return(null, null, keyRemainder, stack)
          } else {
            // keys match, continue search
            walkController.next()
          }
        }
      }
    })
  }

  /*
   * Finds all nodes that store k,v values
   */
  _findValueNodes(onFound: FoundNode): Promise<void> {
    return new Promise(async (resolve) => {
      await this._walkTrie(this.root, (nodeRef, node, key, walkController) => {
        let fullKey = key

        if (node instanceof LeafNode) {
          fullKey = key.concat(node.key)
          // found leaf node!
          onFound(nodeRef, node, fullKey, walkController.next)
        } else if (node instanceof BranchNode && node.value) {
          // found branch with value
          onFound(nodeRef, node, fullKey, walkController.next)
        } else {
          // keep looking for value nodes
          walkController.next()
        }
      })
      resolve()
    })
  }

  /*
   * Finds all nodes that are stored directly in the db
   * (some nodes are stored raw inside other nodes)
   */
  _findDbNodes(onFound: FoundNode): Promise<void> {
    return new Promise(async (resolve) => {
      await this._walkTrie(this.root, (nodeRef, node, key, walkController) => {
        if (isRawNode(nodeRef)) {
          walkController.next()
        } else {
          onFound(nodeRef, node, key, walkController.next)
        }
      })
      resolve()
    })
  }

  /**
   * Updates a node
   * @method _updateNode
   * @private
   * @param {Buffer} key
   * @param {Buffer| String} value
   * @param {Array} keyRemainder
   * @param {Array} stack
   * @returns {Promise}
   */
  async _updateNode(
    k: Buffer,
    value: Buffer,
    keyRemainder: number[],
    stack: TrieNode[],
  ): Promise<void> {
    return new Promise(async (resolve, reject) => {
      const toSave: BatchDBOp[] = []
      const lastNode = stack.pop()
      if (!lastNode) {
        return reject(new Error('Stack underflow'))
      }

      // add the new nodes
      let key = stringToNibbles(k)

      // Check if the last node is a leaf and the key matches to this
      let matchLeaf = false

      if (lastNode instanceof LeafNode) {
        let l = 0

        for (let i = 0; i < stack.length; i++) {
          const n = stack[i]

          if (n instanceof BranchNode) {
            l++
          } else {
            l += n.key.length
          }
        }

        if (
          matchingNibbleLength(lastNode.key, key.slice(l)) === lastNode.key.length &&
          keyRemainder.length === 0
        ) {
          matchLeaf = true
        }
      }

      if (matchLeaf) {
        // just updating a found value
        lastNode.value = value
        stack.push(lastNode as TrieNode)
      } else if (lastNode instanceof BranchNode) {
        stack.push(lastNode)
        if (keyRemainder.length !== 0) {
          // add an extention to a branch node
          keyRemainder.shift()
          // create a new leaf
          const newLeaf = new LeafNode(keyRemainder, value)
          stack.push(newLeaf)
        } else {
          lastNode.value = value
        }
      } else {
        // create a branch node
        const lastKey = lastNode.key
        const matchingLength = matchingNibbleLength(lastKey, keyRemainder)
        const newBranchNode = new BranchNode()

        // create a new extention node
        if (matchingLength !== 0) {
          const newKey = lastNode.key.slice(0, matchingLength)
          const newExtNode = new ExtensionNode(newKey, value)
          stack.push(newExtNode)
          lastKey.splice(0, matchingLength)
          keyRemainder.splice(0, matchingLength)
        }

        stack.push(newBranchNode)

        if (lastKey.length !== 0) {
          const branchKey = lastKey.shift() as number

          if (lastKey.length !== 0 || lastNode instanceof LeafNode) {
            // shriking extention or leaf
            lastNode.key = lastKey
            const formatedNode = this._formatNode(lastNode, false, toSave)
            newBranchNode.setBranch(branchKey, formatedNode as EmbeddedNode)
          } else {
            // remove extention or attaching
            this._formatNode(lastNode, false, toSave, true)
            newBranchNode.setBranch(branchKey, lastNode.value)
          }
        } else {
          newBranchNode.value = lastNode.value
        }

        if (keyRemainder.length !== 0) {
          keyRemainder.shift()
          // add a leaf node to the new branch node
          const newLeafNode = new LeafNode(keyRemainder, value)
          stack.push(newLeafNode)
        } else {
          newBranchNode.value = value
        }
      }

      await this._saveStack(key, stack, toSave)
      resolve()
    })
  }

  // walk tree
  async _walkTrie(root: Buffer, onNode: FoundNode): Promise<void> {
    return new Promise(async (resolve) => {
      const self = this
      root = root || this.root
      let aborted = false

      if (root.toString('hex') === KECCAK256_RLP.toString('hex')) {
        return resolve()
      }

      const node = await this._lookupNode(root)
      await processNode(root, node as TrieNode, [])
      resolve()

      // the maximum pool size should be high enough to utilise the parallelizability of reading nodes from disk and
      // low enough to utilize the prioritisation of node lookup.
      const maxPoolSize = 500
      const taskExecutor = new PrioritizedTaskExecutor(maxPoolSize)

      async function processNode(
        nodeRef: Buffer,
        node: TrieNode,
        key: number[] = [],
      ): Promise<void> {
        return new Promise(async (resolve, reject) => {
          if (!node || aborted) {
            return resolve()
          }

          let stopped = false

          const walkController = {
            stop: function () {
              stopped = true
              resolve()
            },
            // end all traversal and return values to the Promise
            return: function (...args: any) {
              aborted = true
              resolve(args)
            },
            next: function () {
              if (aborted || stopped) {
                return resolve()
              }

              if (node instanceof LeafNode) {
                return resolve()
              }

              let children
              if (node instanceof ExtensionNode) {
                children = [[node.key, node.value]]
              } else if (node instanceof BranchNode) {
                children = node.getChildren().map((b) => [[b[0]], b[1]])
              }
              if (children) {
                for (const child of children) {
                  const keyExtension = child[0] as number[]
                  const childRef = child[1] as Buffer
                  const childKey = key.concat(keyExtension)
                  const priority = childKey.length
                  taskExecutor.execute(priority, async (taskCallback: Function) => {
                    const childNode = await self._lookupNode(childRef)
                    taskCallback()
                    await processNode(childRef, childNode as TrieNode, childKey)
                  })
                }
              }
            },
            only: function (childIndex: number) {
              if (!(node instanceof BranchNode)) {
                return reject(new Error('Expected branch node'))
              }
              const childRef = node.getBranch(childIndex)
              const childKey = key.slice()
              childKey.push(childIndex)
              const priority = childKey.length
              taskExecutor.execute(priority, async (taskCallback: Function) => {
                const childNode = await self._lookupNode(childRef as Buffer)
                taskCallback()
                await processNode(childRef as Buffer, childNode as TrieNode, childKey)
                resolve()
              })
            },
          }

          onNode(nodeRef, node, key, walkController)
        })
      }
    })
  }

  /**
   * saves a stack
   * @method _saveStack
   * @private
   * @param {Array} key - the key. Should follow the stack
   * @param {Array} stack - a stack of nodes to the value given by the key
   * @param {Array} opStack - a stack of levelup operations to commit at the end of this funciton
   * @returns {Promise}
   */
  async _saveStack(key: number[], stack: TrieNode[], opStack: BatchDBOp[]): Promise<void> {
    return new Promise(async (resolve) => {
      let lastRoot

      // update nodes
      while (stack.length) {
        const node = stack.pop() as TrieNode
        if (node instanceof LeafNode) {
          key.splice(key.length - node.key.length)
        } else if (node instanceof ExtensionNode) {
          key.splice(key.length - node.key.length)
          if (lastRoot) {
            node.value = lastRoot
          }
        } else if (node instanceof BranchNode) {
          if (lastRoot) {
            const branchKey = key.pop()
            node.setBranch(branchKey!, lastRoot)
          }
        }
        lastRoot = this._formatNode(node, stack.length === 0, opStack) as Buffer
      }

      if (lastRoot) {
        this.root = lastRoot
      }

      await this.db.batch(opStack)
      resolve()
    })
  }

  _deleteNode(k: Buffer, stack: TrieNode[]): Promise<void> {
    return new Promise(async (resolve, reject) => {
      function processBranchNode(
        key: number[],
        branchKey: number,
        branchNode: TrieNode,
        parentNode: TrieNode,
        stack: TrieNode[],
      ) {
        // branchNode is the node ON the branch node not THE branch node
        if (!parentNode || parentNode instanceof BranchNode) {
          // branch->?
          if (parentNode) {
            stack.push(parentNode)
          }

          if (branchNode instanceof BranchNode) {
            // create an extention node
            // branch->extention->branch
            // @ts-ignore
            const extentionNode = new ExtensionNode([branchKey], null)
            stack.push(extentionNode)
            key.push(branchKey)
          } else {
            const branchNodeKey = branchNode.key
            // branch key is an extention or a leaf
            // branch->(leaf or extention)
            branchNodeKey.unshift(branchKey)
            branchNode.key = branchNodeKey.slice(0)
            key = key.concat(branchNodeKey)
          }
          stack.push(branchNode)
        } else {
          // parent is a extention
          let parentKey = parentNode.key

          if (branchNode instanceof BranchNode) {
            // ext->branch
            parentKey.push(branchKey)
            key.push(branchKey)
            parentNode.key = parentKey
            stack.push(parentNode)
          } else {
            const branchNodeKey = branchNode.key
            // branch node is an leaf or extention and parent node is an exstention
            // add two keys together
            // dont push the parent node
            branchNodeKey.unshift(branchKey)
            key = key.concat(branchNodeKey)
            parentKey = parentKey.concat(branchNodeKey)
            branchNode.key = parentKey
          }

          stack.push(branchNode)
        }

        return key
      }

      let lastNode = stack.pop() as TrieNode
      assert(lastNode)
      let parentNode = stack.pop()
      const opStack: BatchDBOp[] = []

      let key = stringToNibbles(k)

      if (!parentNode) {
        // the root here has to be a leaf.
        this.root = this.EMPTY_TRIE_ROOT
        resolve()
      } else {
        if (lastNode instanceof BranchNode) {
          lastNode.value = null
        } else {
          // the lastNode has to be a leaf if its not a branch. And a leaf's parent
          // if it has one must be a branch.
          if (!(parentNode instanceof BranchNode)) {
            return reject(new Error('Expected branch node'))
          }
          const lastNodeKey = lastNode.key
          key.splice(key.length - lastNodeKey.length)
          // delete the value
          this._formatNode(lastNode, false, opStack, true)
          parentNode.setBranch(key.pop() as number, null)
          lastNode = parentNode
          parentNode = stack.pop()
        }

        // nodes on the branch
        // count the number of nodes on the branch
        const branchNodes: [number, EmbeddedNode][] = lastNode.getChildren()

        // if there is only one branch node left, collapse the branch node
        if (branchNodes.length === 1) {
          // add the one remaing branch node to node above it
          const branchNode = branchNodes[0][1]
          const branchNodeKey = branchNodes[0][0]

          // look up node
          const foundNode = await this._lookupNode(branchNode)
          key = processBranchNode(
            key,
            branchNodeKey,
            foundNode as TrieNode,
            parentNode as TrieNode,
            stack,
          )
          this._saveStack(key, stack, opStack)
        } else {
          // simple removing a leaf and recaluclation the stack
          if (parentNode) {
            stack.push(parentNode)
          }

          stack.push(lastNode)
          this._saveStack(key, stack, opStack)
          resolve()
        }
      }
    })
  }

  // Creates the initial node from an empty tree
  _createInitialNode(key: Buffer, value: Buffer): Promise<void> {
    return new Promise(async (resolve) => {
      const newNode = new LeafNode(stringToNibbles(key), value)
      this.root = newNode.hash()
      await this._putNode(newNode)
      resolve()
    })
  }

  // formats node to be saved by levelup.batch.
  // returns either the hash that will be used key or the rawNode
  _formatNode(
    node: TrieNode,
    topLevel: boolean,
    opStack: BatchDBOp[],
    remove: boolean = false,
  ): Buffer | (EmbeddedNode | null)[] {
    const rlpNode = node.serialize()

    if (rlpNode.length >= 32 || topLevel) {
      const hashRoot = node.hash()

      opStack.push({
        type: 'put',
        key: hashRoot,
        value: rlpNode,
      })

      return hashRoot
    }

    return node.raw()
  }

  /**
   * The `data` event is given an `Object` hat has two properties; the `key` and the `value`. Both should be Buffers.
   * @method createReadStream
   * @memberof Trie
   * @return {stream.Readable} Returns a [stream](https://nodejs.org/dist/latest-v5.x/docs/api/stream.html#stream_class_stream_readable) of the contents of the `trie`
   */
  createReadStream(): ReadStream {
    return new ReadStream(this)
  }

  // creates a new trie backed by the same db
  // and starting at the same root
  copy(): Trie {
    const db = this.db.copy()
    return new Trie(db._leveldb, this.root)
  }

  /**
   * The given hash of operations (key additions or deletions) are executed on the DB
   * @method batch
   * @memberof Trie
   * @example
   * var ops = [
   *    { type: 'del', key: Buffer.from('father') }
   *  , { type: 'put', key: Buffer.from('name'), value: Buffer.from('Yuri Irsenovich Kim') }
   *  , { type: 'put', key: Buffer.from('dob'), value: Buffer.from('16 February 1941') }
   *  , { type: 'put', key: Buffer.from('spouse'), value: Buffer.from('Kim Young-sook') }
   *  , { type: 'put', key: Buffer.from('occupation'), value: Buffer.from('Clown') }
   * ]
   * trie.batch(ops)
   * @param {Array} ops
   * @returns {Promise}
   */
  async batch(ops: BatchDBOp[]): Promise<void> {
    return new Promise(async (resolve, reject) => {
      for await (const op of ops) {
        if (op.type === 'put') {
          if (!op.value) {
            reject(new Error('Invalid batch db operation'))
          }
          await this.put(op.key, op.value)
        } else if (op.type === 'del') {
          await this.del(op.key)
        }
      }
      resolve()
    })
  }

  /**
   * Checks if a given root exists
   */
  async checkRoot(root: Buffer): Promise<boolean> {
    return new Promise(async (resolve) => {
      root = toBuffer(root)
      const value = this._lookupNode(root)
      resolve(!!value)
    })
  }
}
