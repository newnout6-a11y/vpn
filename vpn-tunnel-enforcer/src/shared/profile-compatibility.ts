/** Static core selection only; does not certify runtime connectivity or laboratory admission. */
export type ProfileCompatibility =
  | { version: 1; status: 'selected'; engine: 'sing-box' | 'xray'; reason: 'default' | 'protocol' | 'preference' | 'reality' | 'xray-transport' | 'native-xray' }
  | { version: 1; status: 'rejected'; engine: null; reason: 'native-xray' | 'xray-transport' }
