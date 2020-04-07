import fs from 'fs'
import path from 'path'
import { GroupElement, ZqElement } from '../datatypes'

export const performanceTimer = performance || Date // performance not supported on Safari
export const testVectorDirectory = 'src/__tests__/TestVectors'

export function readNumberList(s: string): number[] {
    const elements = s.split(',')
    const array = new Array()

    for (let i = 0; i < elements.length; i++) {
        const n = elements[i].valueOf()
        array[i] = parseInt(n, 10)
    }

    return array
}
export function readHexString(hexString: string): Uint8Array {
    const array = new Array()
    let index = 0
    if (hexString.length % 2 !== 0) {
        // prepend 0
        hexString = '0' + hexString
    }

    for (let i = 0; i < hexString.length; i += 2) {
        array[index++] = parseInt('0x' + hexString.substr(i, 2), 16)
    }

    const result = new Uint8Array(array)
    return result
}

function readFileData(filename: string): string {
    return fs.readFileSync(path.resolve(testVectorDirectory, filename), 'utf8')
}

export function readFileDataInDictionary(filename: string): { [k: string]: any } {
    const fileData = readFileData(filename)

    const lines = fileData.split('\r\n')
    const dictionary = {}
    for (let j = 1; j < lines.length; j++) {
        // skip the file header in line 0
        const lineData = lines[j].split(' = ')
        dictionary[lineData[0]] = lineData[1]
    }
    return dictionary
}

export function readTestVectors(filename: string): { [k: string]: any } {
    const vectorsData = readFileData(filename)
    // put each test vector variable in a dictionary
    const lines = vectorsData.split('\r\n')
    const vectors = {}
    for (let j = 1; j < lines.length; j++) {
        // skip the header
        const lineData = lines[j].split(' = ')
        vectors[lineData[0]] = lineData[1]
    }
    return vectors
}

export function readRecommendedParams(filename: string): { [k: string]: any } {
    const paramsData = readFileData(filename)

    // put each test vector variable in a dictionary
    const lines = paramsData.split('\r\n')
    const vectors = {}
    for (let j = 1; j < lines.length; j++) {
        // skip the header
        const lineData = lines[j].split(' = ')
        vectors[lineData[0]] = lineData[1]
    }
    return vectors
}

export function readVectorElement(group, vectors, label, isEcGq = false): GroupElement {
    if (isEcGq) {
        return group.createPoint(readHexString(vectors[label + '.x']), readHexString(vectors[label + '.y']))
    } else {
        return group.createElementFromBytes(readHexString(vectors[label]))
    }
}

export function readVectorZqElement(group, vectors, label): ZqElement {
    return group.createElementFromBytes(readHexString(vectors[label]))
}
