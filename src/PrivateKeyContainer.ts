/*
 * Created April 2020
 *
 * Copyright (c) 2020 Privacy Research, LLC
 *
 *  Licensed under GPL v3 (https://www.gnu.org/licenses/gpl-3.0.en.html)
 *
 */

export interface PrivateKeyContainer {
    getPrivateKeyBytes: () => Uint8Array
}

export class InMemoryPrivateKeyContainer implements PrivateKeyContainer {
    constructor(private _bytes: Uint8Array) {}
    getPrivateKeyBytes(): Uint8Array {
        return this._bytes
    }
}
