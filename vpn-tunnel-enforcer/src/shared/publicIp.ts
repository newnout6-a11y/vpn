/** Public-IP observations alone cannot prove a physical-adapter leak. */
export type PublicIpVerdict = 'passed' | 'indeterminate' | 'not-checked' | 'failed'
export interface PublicIpEvidence {
  vpnIp: string | null
  verdict: PublicIpVerdict
}
export interface PublicIpInfo extends Partial<PublicIpEvidence> {
  ip: string | null
  isLeak: boolean
}
