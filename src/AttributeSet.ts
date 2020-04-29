/*
 * Created on Wed Apr 15 2020
 *
 * Copyright (c) 2020 Privacy Research, LLC
 *
 *  Licensed under GPL v3 (https://www.gnu.org/licenses/gpl-3.0.en.html)
 *
 */

import { Attribute } from './datatypes'

export enum AttributeType {
    String,
    Null,
    Number,
    Boolean,
}

export interface DecoratedAttribute {
    name: string
    type: AttributeType
    value: string | boolean | number | null
    hashed: boolean

    // format is "type || namelength || name || length || value" where length is number of array entries
    encode: () => Attribute
}

function stringToArray(s: string): number[] {
    const bytes = s.split('').map((c: string) => c.charCodeAt(0))
    return [bytes.length, ...bytes]
}

export function readAttribute(encoded: number[]): DecoratedAttribute {
    const type = encoded[0] as AttributeType
    switch (type) {
        case AttributeType.String:
            return StringAttribute.decode(encoded)
        case AttributeType.Number:
            return NumberAttribute.decode(encoded)
        case AttributeType.Boolean:
            return BooleanAttribute.decode(encoded)
        case AttributeType.Null:
            return NullAttribute.decode(encoded)
    }
}

export class StringAttribute implements DecoratedAttribute {
    name: string
    type = AttributeType.String
    value: string
    hashed: boolean

    constructor(name: string, value: string) {
        this.name = name
        this.value = value
        this.hashed = value.length >= 32 // hash it if it doesn't fit in Zq. TODO: check more carefully
    }

    encode(): number[] {
        return [this.type, ...stringToArray(this.name), ...stringToArray(this.value)]
    }

    static decode(arr: Attribute): StringAttribute {
        const nameLength = arr[1]
        const nameBytes = arr.slice(2, 2 + nameLength)
        const name = String.fromCharCode(...nameBytes)

        const valueLength = arr[2 + nameLength]
        const valueBytes = arr.slice(3 + nameLength)
        const value = String.fromCharCode(...valueBytes)
        return new StringAttribute(name, value)
    }
}

export class NumberAttribute implements DecoratedAttribute {
    name: string
    type = AttributeType.Number
    value: number
    hashed: boolean

    constructor(name: string, value: number) {
        this.name = name
        this.value = value
        this.hashed = false
    }

    encode(): number[] {
        return [this.type, ...stringToArray(this.name), this.value]
    }

    static decode(arr: Attribute): NumberAttribute {
        const nameLength = arr[1]
        const nameBytes = arr.slice(2, 2 + nameLength)
        const name = String.fromCharCode(...nameBytes)
        return new NumberAttribute(name, arr[2 + nameLength])
    }
}

export class BooleanAttribute implements DecoratedAttribute {
    name: string
    type = AttributeType.Boolean
    value: boolean
    hashed = false

    constructor(name: string, value: boolean) {
        this.name = name
        this.value = value
    }

    encode(): number[] {
        return [this.type, ...stringToArray(this.name), this.value ? 1 : 0]
    }

    static decode(arr: Attribute): BooleanAttribute {
        const nameLength = arr[1]
        const nameBytes = arr.slice(2, 2 + nameLength)
        const name = String.fromCharCode(...nameBytes)
        return new BooleanAttribute(name, !!arr[2 + nameLength])
    }
}

export class NullAttribute implements DecoratedAttribute {
    name: string
    type = AttributeType.Null
    value = null
    hashed = false

    constructor(name: string) {
        this.name = name
    }

    encode(): number[] {
        return [this.type, ...stringToArray(this.name)]
    }

    static decode(arr: Attribute): NullAttribute {
        const nameLength = arr[1]
        const nameBytes = arr.slice(2, 2 + nameLength)
        const name = String.fromCharCode(...nameBytes)
        return new NullAttribute(name)
    }
}

export class AttributeSet {
    attributes: DecoratedAttribute[] = []

    addStringAttribute(name: string, value: string): void {
        this.attributes.push(new StringAttribute(name, value))
    }

    addNumberAttribute(name: string, value: number): void {
        this.attributes.push(new NumberAttribute(name, value))
    }

    addBooleanAttribute(name: string, value: boolean): void {
        this.attributes.push(new BooleanAttribute(name, value))
    }

    addNullAttribute(name: string): void {
        this.attributes.push(new NullAttribute(name))
    }

    encode(): Attribute[] {
        return this.attributes.map((attr: DecoratedAttribute) => attr.encode())
    }

    indexOfAttribute(name: string): number {
        const idx = this.attributes.findIndex((attr: DecoratedAttribute) => attr.name === name)
        return idx
    }

    get json(): { [k: string]: string | number | boolean | null } {
        const result = {}
        for (const attr of this.attributes) {
            result[attr.name] = attr.value
        }
        return result
    }

    static decode(encoded: Attribute[]): AttributeSet {
        // not very OOPy, ph well :)
        const result = new AttributeSet()
        result.attributes = encoded.map(readAttribute)
        return result
    }

    static fromJSON(json: { [k: string]: string | number | boolean | null }): AttributeSet {
        const result = new AttributeSet()
        for (const name of Object.keys(json)) {
            const value = json[name]
            let attr: DecoratedAttribute | undefined
            switch (typeof value) {
                case 'string':
                    attr = new StringAttribute(name, value as string)
                    break
                case 'number':
                    attr = new NumberAttribute(name, value as number)
                    break
                case 'boolean':
                    attr = new BooleanAttribute(name, value as boolean)
                    break
                case 'object':
                    if (value === null) {
                        attr = new NullAttribute(name)
                    }
                    break
            }
            if (attr) {
                result.attributes.push(attr)
            }
        }
        return result
    }
}
