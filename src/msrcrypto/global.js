//*********************************************************
//
//    Original file: Copyright (c) Microsoft. All rights reserved.
//    Modifications for TypeScript conversion: Copyright (c) Privacy Research, LLC
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//
//*********************************************************

/// #region JSCop/JsHint

/* global self */
/* jshint -W098 */
/* W098 is 'defined but not used'. These properties are used in other scripts. */

/// //<reference path="jsCopDefs.js" />

// Sets the url to for this script.
// We need this to pass to webWorkers later to instantiate them.

/// <dictionary>fprng</dictionary>

/// #endregion JSCop/JsHint

// Collection of hash functions for global availability.
// Each hashfunction will add itself to the collection as it is evaluated.
export const msrcryptoHashFunctions = {}

// Property setter/getter support IE9+.
export const setterSupport = (function () {
  try {
    Object.defineProperty({}, 'oncomplete', {})
    return true
  } catch (ex) {
    return false
  }
})()

export function createProperty(parentObject, propertyName, /*@dynamic*/ initialValue, getterFunction, setterFunction) {
  /// <param name="parentObject" type="Object"/>
  /// <param name="propertyName" type="String"/>
  /// <param name="initialValue" type="Object"/>
  /// <param name="getterFunction" type="Function"/>
  /// <param name="setterFunction" type="Function" optional="true"/>

  if (!setterSupport) {
    parentObject[propertyName] = initialValue
    return
  }

  const setGet = {}

  getterFunction && (setGet.get = getterFunction)
  setterFunction && (setGet.set = setterFunction)

  Object.defineProperty(parentObject, propertyName, setGet)
}
