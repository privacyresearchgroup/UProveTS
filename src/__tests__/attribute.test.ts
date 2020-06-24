/*
 * Created April 2020
 *
 * Copyright (c) 2020 Privacy Research, LLC
 *
 *  Licensed under GPL v3 (https://www.gnu.org/licenses/gpl-3.0.en.html)
 *
 */
import { AttributeSet, AttributeType, StringAttribute } from '../AttributeSet'

const testjson = {
    aBool: false,
    name: 'Leonidas',
    motto: 'μολὼν λαβέ',
    num: 42,
    hobbies: null,
}

test('to and from JSON', () => {
    const as = AttributeSet.fromJSON(testjson)
    expect(as.attributes.length).toBe(5)
    expect(as.attributes[0].type).toBe(AttributeType.Boolean)
    expect(as.attributes[0].name).toBe('aBool')

    const encoded = as.encode()
    console.log(encoded)
    expect(encoded[0]).toEqual([AttributeType.Boolean, 5, 97, 66, 111, 111, 108, 0])

    const as2 = AttributeSet.decode(encoded)
    const json2 = as2.json
    console.log(json2)
    expect(json2).toEqual(testjson)

    expect(as.indexOfAttribute('motto')).toBe(2)
    expect(as2.indexOfAttribute('num')).toBe(3)
})

test(`encode/decode large strings`, () => {
    const bigArray = new Array(200000).fill(88)
    const prefix = [0, 1, 88, 20000]
    const bigAttr = [...prefix, ...bigArray]
    const strattr = StringAttribute.decode(bigAttr)
    console.log({ strattr: { name: strattr.name, val: strattr.value.slice(0, 20), len: strattr.value.length } })
})
