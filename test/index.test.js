const { assert }  = require('chai')
const lib = require("../")
const saltpack = lib.init()

it('can generate keys', async () => {
  const sp = await saltpack

  const keys = sp.keyGen()
  assert.hasAllKeys(keys, ['signing']);

  const signing = keys.signing
  assert.hasAllKeys(signing, ['type', 'public', 'private']);
  assert.equal(signing.type, 'signing')
})

it('can sign values', async () => {
  const sp = await saltpack

  const keys = sp.keyGen()
  const signed = sp.signValue(keys.signing, "test")
  const value = sp.verifyValue(keys.signing.public, signed)
  assert.equal(value, "test")
})

it('can fail signing values', async () => {
  const sp = await saltpack

  const keys1 = sp.keyGen()
  const keys2 = sp.keyGen()
  const signed = sp.signValue(keys1.signing, "test")
  assert.throws(() => {
    sp.verifyValue(keys2.signing.public, signed)
  }, "keys do not match")
})
