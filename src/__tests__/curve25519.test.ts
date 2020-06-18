import Curve25519, { MontgomeryPointWrapper } from '../Curve25519'
import { residuesEqual } from '@rolfe/pr-math'

test('generators are correct', () => {
    const numGenerators = 51
    const generators: MontgomeryPointWrapper[] = []
    for (let i = 0; i < numGenerators; ++i) {
        generators.push(Curve25519.computeGeneratorForIndex(i))
    }
    const b64s = generators.map((wp: MontgomeryPointWrapper) => wp.montPoint.toBase64())
    console.log({ b64s })

    const preGenGenerators = Curve25519.getPreGenGenerators(50)
    console.log(`num pregen generators`, preGenGenerators.length)
    for (let i = 0; i < numGenerators; ++i) {
        expect(generators[i].equals(preGenGenerators[i + 1]))
    }
})
