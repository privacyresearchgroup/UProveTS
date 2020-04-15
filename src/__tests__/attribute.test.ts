import { AttributeSet, AttributeType } from '../AttributeSet'

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
})
