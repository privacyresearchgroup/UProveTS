export interface PrivateKeyContainer {
    getPrivateKeyBytes: () => Uint8Array
}

export class InMemoryPrivateKeyContainer implements PrivateKeyContainer {
    constructor(private _bytes: Uint8Array) {}
    getPrivateKeyBytes(): Uint8Array {
        return this._bytes
    }
}
