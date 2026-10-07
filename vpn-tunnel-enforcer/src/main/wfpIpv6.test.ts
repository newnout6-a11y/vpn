// AT-03-001/003/004/007/010/012: managed policy/native ABI, mocked OS effects.
import { execFileSync } from 'child_process'
import { readFileSync, mkdirSync, mkdtempSync, writeFileSync, unlinkSync, rmdirSync } from 'fs'
import { join } from 'path'
import { createHash, randomUUID } from 'crypto'
import { beforeEach, describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({ owner: null as any, source: null as string | null, resolve6: vi.fn(), cancelDns: vi.fn() }))
vi.mock('dns/promises', () => ({ Resolver: class {
  constructor(public options: unknown) {}
  resolve6(host: string) { return state.resolve6(host) }
  cancel() { state.cancelDns() }
} }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./admin', () => ({ isProcessElevated: async () => false }))
vi.mock('electron', () => ({ app: { isPackaged: false } }))
vi.mock('./recoveryManifest', () => ({ readRecoveryManifest: async (_name: string, validate: Function) => state.owner ? validate(state.owner) : null }))
vi.mock('fs/promises', async importOriginal => {
  const actual = await importOriginal<typeof import('fs/promises')>()
  return { ...actual, readFile: (...args: Parameters<typeof actual.readFile>) => state.source === null ? actual.readFile(...args) : Promise.resolve(state.source) }
})
import { applyWfpIpv6Policy, hasWfpIpv6Protection, prepareWfpIpv6Policy, prepareWfpIpv6Exceptions, removeWfpIpv6Protection, validateWfpIpv6Policy, verifyWfpIpv6Policy, reserveWfpIpv6Priority, wfpPrelude, WFP_SOURCE_SHA256, synthesizeNat64Endpoint, type WfpIpv6Policy } from './wfpIpv6'
import { execElevatedPs } from './elevatedPsHelper'
const source = readFileSync(join(process.cwd(), 'resources/vpnte-wfp-ipv6.cs'), 'utf8').replace(/\r\n/g, '\n')
const blocks = (): WfpIpv6Policy => ({ schemaVersion: 1, rules: ['connect','accept','boot'].map(layer => ({ id: randomUUID(), role: 'block', remote: '', appId: '', luid: '', originalApp: false, inbound: layer === 'accept', boot: layer === 'boot' })) })
beforeEach(() => {
  state.owner = { schemaVersion: 1, owner: 'VPNTE', interfaceGuid: '11111111-1111-1111-1111-111111111111' }; state.source = source
  state.resolve6.mockReset().mockResolvedValue([]); state.cancelDns.mockReset()
})
describe('independent IPv6 WFP lifecycle', () => {
  it('pins the exact same source in main and boot recovery before compilation (AT-03-012)', async () => {
    expect(createHash('sha256').update(source).digest('hex')).toBe(WFP_SOURCE_SHA256)
    expect(readFileSync(join(process.cwd(), 'resources/vpnte-recover.ps1'), 'utf8')).toContain(`$hash -ne '${WFP_SOURCE_SHA256}'`)
    state.source = source + '\n// modified'
    await expect(wfpPrelude()).rejects.toThrow('integrity mismatch')
  })
  it('refuses IPv6 preparation without proven TUN ownership before any native call (AT-03-002/012)', async () => {
    state.owner = null
    const run = vi.fn()
    await expect(prepareWfpIpv6Policy({ corePrograms: [], tunAlias: 'VPNTE', apps: [], cidrs: [] }, run)).rejects.toThrow('identity is required')
    expect(run).not.toHaveBeenCalled()
  })
  it('builds independent blocks and narrow app/address/interface VPN permits (AT-03-001/010)', async () => {
    state.resolve6.mockResolvedValue(['64:ff9b::cb00:7101'])
    const run = vi.fn(async (_script: string) => ({ stdout: 'WFP_PREPARED:' + JSON.stringify({ tunLuid: '12', ipv6Uplink: true, appIds: [], vpn: [{ appId: 'AABB', remote: '64:ff9b::cb00:7101/128', luid: '17' }] }) }))
    const policy = await prepareWfpIpv6Policy({ corePrograms: ['C:\\VPNTE\\core.exe'], serverHost: 'vpn.example', tunAlias: 'VPNTE', apps: [], cidrs: [] }, run)
    expect(policy.rules.filter(r => r.role === 'block')).toHaveLength(3)
    expect(policy.rules.filter(r => r.role === 'vpn')).toEqual(expect.arrayContaining([expect.objectContaining({ appId: 'AABB', remote: '64:ff9b::cb00:7101/128', luid: '17', inbound: false })]))
    expect(policy.rules.filter(r => r.role === 'exception-ip')).toEqual([])
    const script = run.mock.calls[0][0]
    expect(script).toContain('Find-NetRoute')
    expect(script).toContain('Owned TUN subnet mismatch')
    expect(script).not.toContain('Disable-NetAdapterBinding')
  })
  it('refuses an incomplete native transport plan instead of reporting IPv6 ready (AT-03-010)', async () => {
    state.resolve6.mockResolvedValue(['2001:db8::1'])
    const run = vi.fn(async (_script: string) => ({ stdout: 'WFP_PREPARED:{"tunLuid":"12","appIds":[],"vpn":[],"ipv6Uplink":true}' }))
    await expect(prepareWfpIpv6Policy({ corePrograms: ['C:\\VPNTE\\core.exe'], serverHost: 'vpn.example', tunAlias: 'VPNTE', apps: [], cidrs: [] }, run)).rejects.toThrow('Incomplete IPv6 transport scopes')
  })
  it.each(['203.0.113.1', 'vpn.example'])('skips DNS on an IPv4-only uplink for %s without an extra native roundtrip (AT-03-010)', async serverHost => {
    const run = vi.fn(async () => ({ stdout: 'WFP_PREPARED:{"tunLuid":"12","appIds":[],"vpn":[],"ipv6Uplink":false}' }))
    const policy = await prepareWfpIpv6Policy({ corePrograms: ['C:\\VPNTE\\core.exe'], serverHost, tunAlias: 'VPNTE', apps: [], cidrs: [] }, run)
    expect(state.resolve6).not.toHaveBeenCalled()
    expect(run).toHaveBeenCalledOnce()
    expect(policy.rules.filter(r => r.role === 'block')).toHaveLength(3)
    expect(policy.rules.filter(r => r.role === 'vpn')).toEqual([])
  })
  it('refuses an unknown physical uplink before querying DNS (AT-03-010)', async () => {
    const run = vi.fn(async () => ({ stdout: 'WFP_PREPARED:{"tunLuid":"12","appIds":[],"vpn":[]}' }))
    await expect(prepareWfpIpv6Policy({ corePrograms: [], serverHost: 'vpn.example', tunAlias: 'VPNTE', apps: [], cidrs: [] }, run)).rejects.toThrow('uplink not verified')
    expect(state.resolve6).not.toHaveBeenCalled()
  })
  it('bounds stalled DNS discovery and keeps IPv6 blocked without transport permits (AT-03-010)', async () => {
    vi.useFakeTimers()
    try {
      state.resolve6.mockImplementation(() => new Promise((_resolve, reject) => {
        state.cancelDns.mockImplementation(() => reject(Object.assign(new Error('cancelled'), { code: 'ECANCELLED' })))
      }))
      const run = vi.fn(async () => ({ stdout: 'WFP_PREPARED:{"tunLuid":"12","appIds":[],"vpn":[],"ipv6Uplink":true}' }))
      const preparing = prepareWfpIpv6Policy({ corePrograms: ['C:\\VPNTE\\core.exe'], serverHost: '203.0.113.1', tunAlias: 'VPNTE', apps: [], cidrs: [] }, run)
      await vi.advanceTimersByTimeAsync(1500)
      const policy = await preparing
      expect(state.cancelDns).toHaveBeenCalledOnce()
      expect(state.resolve6).toHaveBeenCalledWith('ipv4only.arpa')
      expect(policy.rules.filter(r => r.role === 'block')).toHaveLength(3)
      expect(policy.rules.filter(r => r.role === 'vpn')).toEqual([])
      expect(run).toHaveBeenCalledOnce()
      expect(vi.getTimerCount()).toBe(0)
    } finally { vi.useRealTimers() }
  })
  it('cancels DNS immediately after read-only preparation and before policy effects (AT-03-007/010)', async () => {
    const controller = new AbortController()
    let started!: () => void
    const querying = new Promise<void>(resolve => { started = resolve })
    state.resolve6.mockImplementation(() => new Promise((_resolve, reject) => {
      state.cancelDns.mockImplementation(() => reject(Object.assign(new Error('cancelled'), { code: 'ECANCELLED' })))
      started()
    }))
    const run = vi.fn(async () => ({ stdout: 'WFP_PREPARED:{"tunLuid":"12","appIds":[],"vpn":[],"ipv6Uplink":true}' }))
    const preparing = prepareWfpIpv6Policy({ corePrograms: [], serverHost: 'vpn.example', tunAlias: 'VPNTE', apps: [], cidrs: [], signal: controller.signal }, run)
    const rejected = expect(preparing).rejects.toMatchObject({ name: 'AbortError' })
    await querying
    controller.abort()
    await rejected
    expect(state.cancelDns).toHaveBeenCalledOnce()
    expect(run).toHaveBeenCalledOnce()
  })
  it('does not discover DNS for literal IPv6 endpoints or already cancelled starts (AT-03-010)', async () => {
    const run = vi.fn(async () => ({ stdout: 'WFP_PREPARED:{"tunLuid":"12","appIds":[],"vpn":[],"ipv6Uplink":true}' }))
    await prepareWfpIpv6Policy({ corePrograms: [], serverHost: '2001:db8::1', tunAlias: 'VPNTE', apps: [], cidrs: [] }, run)
    expect(state.resolve6).not.toHaveBeenCalled()
    const controller = new AbortController(); controller.abort(); run.mockClear()
    await expect(prepareWfpIpv6Policy({ corePrograms: [], serverHost: 'vpn.example', tunAlias: 'VPNTE', apps: [], cidrs: [], signal: controller.signal }, run)).rejects.toMatchObject({ name: 'AbortError' })
    expect(run).not.toHaveBeenCalled()
  })
  it.each(['ENODATA', 'ENOTFOUND', 'ETIMEOUT'])('omits permits after DNS %s without bypassing IPv6 blocks (AT-03-010)', async code => {
    state.resolve6.mockRejectedValue(Object.assign(new Error('DNS unavailable'), { code }))
    const run = vi.fn(async () => ({ stdout: 'WFP_PREPARED:{"tunLuid":"12","appIds":[],"vpn":[],"ipv6Uplink":true}' }))
    const policy = await prepareWfpIpv6Policy({ corePrograms: ['C:\\VPNTE\\core.exe'], serverHost: 'vpn.example', tunAlias: 'VPNTE', apps: [], cidrs: [] }, run)
    expect(policy.rules.filter(r => r.role === 'vpn')).toEqual([])
    expect(policy.rules.filter(r => r.role === 'block')).toHaveLength(3)
  })
  it('accepts the actual pinned generated WFP scripts through the dedicated helper policy (AT-03-012)', async () => {
    const check = async (script: string) => {
      // A non-elevated fixture must reach unavailability, never policy rejection.
      await expect(execElevatedPs(script, 1000, 'wfp-ipv6')).rejects.toMatchObject({ code: 'elevated-helper-unavailable' })
      return { stdout: 'WFP_IPV6_VERIFIED\nWFP_IPV6_REMOVED\nWFP_COUNT:0\nWFP_APPS:[]\nWFP_PREPARED:{"tunLuid":"12","appIds":[],"vpn":[],"ipv6Uplink":true}' }
    }
    const policy = blocks()
    await applyWfpIpv6Policy(policy, check)
    await verifyWfpIpv6Policy(policy, check)
    await removeWfpIpv6Protection(check)
    expect(await hasWfpIpv6Protection(check)).toBe(false)
    await prepareWfpIpv6Exceptions(policy, [], [], check)
    await prepareWfpIpv6Policy({ corePrograms: [], tunAlias: 'VPNTE', apps: [], cidrs: [] }, check)
  })
  it.each([
    ['2001:db8::', 32, '2001:db8:c000:aa::', '2001:db8:c000:ab::', '2001:db8:cb00:7101::'],
    ['2001:db8:100::', 40, '2001:db8:1c0:0:aa::', '2001:db8:1c0:0:ab::', '2001:db8:1cb:71:1::'],
    ['2001:db8:100::', 48, '2001:db8:100:c000:0:aa00::', '2001:db8:100:c000:0:ab00::', '2001:db8:100:cb00:71:100::'],
    ['2001:db8:100:200::', 56, '2001:db8:100:2c0:0:aa::', '2001:db8:100:2c0:0:ab::', '2001:db8:100:2cb:0:7101::'],
    ['2001:db8:100:200::', 64, '2001:db8:100:200:c0:0:aa00:0', '2001:db8:100:200:c0:0:ab00:0', '2001:db8:100:200:cb:71:100:0'],
    ['64:ff9b::', 96, '64:ff9b::c000:aa', '64:ff9b::c000:ab', '64:ff9b::cb00:7101']
  ])('synthesizes the exact VPN endpoint for DNS64 %s/%i (AT-03-010)', (_prefix, _length, a, b, expected) => {
    expect(synthesizeNat64Endpoint('203.0.113.1', [a as string, b as string])).toEqual([expected])
    expect(synthesizeNat64Endpoint('203.0.113.1', [a as string])).toEqual([])
  })
  it.each(['appId','remote','luid'])('rejects a missing %s in a VPN exception (AT-03-010)', field => {
    const policy = blocks()
    policy.rules.push({ ...policy.rules[0], id: randomUUID(), role: 'vpn', appId: 'AABB', remote: '2001:db8::1/128', luid: '17', [field]: '' })
    expect(() => validateWfpIpv6Policy(policy)).toThrow('requires app, exact address and interface')
  })
  it('rejects a broad NAT64 permit, wildcards and malformed LUIDs (AT-03-010/012)', () => {
    for (const scope of [{ remote: '64:ff9b::/96' }, { luid: '18446744073709551616' }, { appId: "';Invoke-Expression" }]) {
      const policy = blocks()
      policy.rules.push({ ...policy.rules[0], id: randomUUID(), role: 'vpn', appId: 'AABB', remote: '2001:db8::1/128', luid: '17', ...scope })
      expect(() => validateWfpIpv6Policy(policy)).toThrow()
    }
  })
  it('requires separate explicit native proof for apply, inspect and removal (AT-03-007)', async () => {
    const run = vi.fn(async () => ({ stdout: '' }))
    await expect(applyWfpIpv6Policy(blocks(), run)).rejects.toThrow('apply not verified')
    await expect(verifyWfpIpv6Policy(blocks(), run)).rejects.toThrow('coverage not verified')
    await expect(removeWfpIpv6Protection(run)).rejects.toThrow('cleanup not verified')
    await expect(hasWfpIpv6Protection(run)).rejects.toThrow('marker')
    await expect(reserveWfpIpv6Priority(run)).rejects.toThrow('priority not verified')
  })
  it('reserves only owned metadata with transaction/read-back before core startup (AT-03-010)', async () => {
    const run = vi.fn(async (_script: string) => ({ stdout: 'WFP_PRIORITY_VERIFIED' }))
    await reserveWfpIpv6Priority(run)
    const script = run.mock.calls[0][0].slice((await wfpPrelude()).length)
    expect(script).toContain('$engine.Begin()')
    expect(script).toContain('$engine.EnsureSublayer(); $engine.Commit()')
    expect(script).toContain('$engine.Abort(); throw')
    expect(script).toContain('$engine.VerifyPriority()')
    expect(script).not.toContain('Policy]::Apply')
    expect(script).not.toContain('$engine.Add')
  })
  it('live exceptions preserve every core/block/TUN scope and apply only explicit IPv6 exceptions (AT-03-008/010)', async () => {
    const old = blocks()
    const run = vi.fn(async () => ({ stdout: 'WFP_APPS:["AABB"]' }))
    const next = await prepareWfpIpv6Exceptions(old, ['C:\\Apps\\allowed.exe'], ['192.0.2.1', '2001:db8::5'], run)
    expect(next.rules.slice(0, 3)).toEqual(old.rules)
    expect(next.rules.filter(r => r.role === 'exception-ip').map(r => r.remote)).toEqual(['2001:db8::5/128','2001:db8::5/128'])
    expect(next.rules.filter(r => r.role === 'exception-app').map(r => r.appId)).toEqual(['AABB','AABB'])
  })
})

describe.skipIf(process.platform !== 'win32' && !process.env.VPNTE_PWSH)('compiled production C# policy with fake WFP engine', () => {
  it('executes generated PowerShell rules and transaction/ABI regressions without changing the network', async () => {
    const fixture = `
namespace VPNTE.IPv6.Tests {
  public sealed class Fake : IEngine {
    public System.Collections.Generic.List<Rule> Rules = new System.Collections.Generic.List<Rule>();
    System.Collections.Generic.List<Rule> before;
    public int Adds, Commits, Aborts, Reads; public bool FailAdd, FailReadback, FailCommit, FailDelete, FailAfterCommit;
    public void Begin(){before=Rules.ToList();} public void EnsureSublayer(){} public void VerifyPriority(){}
    public void Commit(){if(FailCommit)throw new Exception("commit failure");Commits++;}
    public void Abort(){Rules=before;Aborts++;} public void Dispose(){}
    public Rule[] ReadOwned(){Reads++;if((FailReadback && Adds>0) || (FailAfterCommit && Commits>0))return new Rule[0];return Rules.ToArray();}
    public void Add(Rule r){Adds++;if(FailAdd)throw new Exception("add failure");Rules.Add(r);}
    public void Delete(Guid id){if(FailDelete)throw new Exception("delete failure");Rules.RemoveAll(r=>r.Id==id);}
  }
  public static class Run {
    static void Assert(bool b,string why){if(!b)throw new Exception(why);}
    static Rule[] Blocks(){return new[]{new Rule{Id=Guid.NewGuid(),Role="block"},new Rule{Id=Guid.NewGuid(),Role="block",Inbound=true},new Rule{Id=Guid.NewGuid(),Role="block",Boot=true}};}
    public static void All(){
      var layout=typeof(NativeEngine); var flags=System.Reflection.BindingFlags.NonPublic;
      Assert(Marshal.SizeOf(layout.GetNestedType("Filter",flags))==200,"FWPM_FILTER0 x64 ABI");
      Assert((ushort)layout.GetField("SublayerWeight",flags|System.Reflection.BindingFlags.Static).GetRawConstantValue()==0xffff,"request highest priority and verify actual priority");
      var checkFlags=layout.GetMethod("FilterFlagsValid",flags|System.Reflection.BindingFlags.Static);
      foreach(var mask in new uint[]{1,65})Assert((bool)checkFlags.Invoke(null,new object[]{mask,false}),"persistent indexed read-back");
      foreach(var mask in new uint[]{2,34,66,98})Assert((bool)checkFlags.Invoke(null,new object[]{mask,true}),"boot indexed/disabled read-back");
      foreach(var mask in new uint[]{0,2,9,33,129})Assert(!(bool)checkFlags.Invoke(null,new object[]{mask,false}),"unknown/disabled persistent flags rejected");
      var filterType=layout.GetNestedType("Filter",flags);var actionType=layout.GetNestedType("Action",flags);
      var filter=Activator.CreateInstance(filterType);var action=Activator.CreateInstance(actionType);
      actionType.GetField("Type").SetValue(action,0x1002u);filterType.GetField("Action").SetValue(filter,action);
      filterType.GetField("Flags").SetValue(filter,8u);filterType.GetField("Layer").SetValue(filter,new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"));
      var checkPriority=layout.GetMethod("HigherHardPermit",flags|System.Reflection.BindingFlags.Static);
      Assert((bool)checkPriority.Invoke(null,new object[]{filter,(ushort)65535,(ushort)65533}),"higher hard permit detected");
      Assert((bool)checkPriority.Invoke(null,new object[]{filter,(ushort)65533,(ushort)65533}),"equal hard permit is ambiguous");
      Assert(!(bool)checkPriority.Invoke(null,new object[]{filter,(ushort)65532,(ushort)65533}),"lower permit cannot bypass block");
      filterType.GetField("Flags").SetValue(filter,40u);
      Assert(!(bool)checkPriority.Invoke(null,new object[]{filter,(ushort)65535,(ushort)65533}),"disabled permit is inactive");
      // A deciding driver callout can return PERMIT and clear ACTION_WRITE.
      // Its future result cannot be proven safe from the static action alone.
      foreach(var layerId in new[]{"4a72393b-319f-44bc-84c3-ba54dcb3b6b4","a3b42c97-9f04-4672-b87e-cee9c483257f","a3b3ab6b-3564-488c-9117-f34e82142763"}){
        filterType.GetField("Layer").SetValue(filter,new Guid(layerId));
        foreach(var kind in new uint[]{0x5003,0x4005})foreach(var mask in new uint[]{0,8,16,24}){
          actionType.GetField("Type").SetValue(action,kind);filterType.GetField("Action").SetValue(filter,action);filterType.GetField("Flags").SetValue(filter,mask);
          Assert((bool)checkPriority.Invoke(null,new object[]{filter,(ushort)65535,(ushort)65533}),"higher deciding callout must be rejected");
          Assert((bool)checkPriority.Invoke(null,new object[]{filter,(ushort)65533,(ushort)65533}),"equal deciding callout is ambiguous");
          Assert(!(bool)checkPriority.Invoke(null,new object[]{filter,(ushort)65532,(ushort)65533}),"lower callout cannot override hard block");
          filterType.GetField("Flags").SetValue(filter,mask|32u);
          Assert(!(bool)checkPriority.Invoke(null,new object[]{filter,(ushort)65535,(ushort)65533}),"disabled callout is inactive");
        }
        foreach(var kind in new uint[]{0x6004,0x1001,0x1002}){
          actionType.GetField("Type").SetValue(action,kind);filterType.GetField("Action").SetValue(filter,action);filterType.GetField("Flags").SetValue(filter,0u);
          Assert(!(bool)checkPriority.Invoke(null,new object[]{filter,(ushort)65535,(ushort)65533}),"inspection, block and soft permit do not bypass protection");
        }
      }
      Assert(Marshal.SizeOf(layout.GetNestedType("Sublayer",flags))==72,"FWPM_SUBLAYER0 x64 ABI");
      Assert(Marshal.SizeOf(layout.GetNestedType("Condition",flags))==40,"FWPM_FILTER_CONDITION0 x64 ABI");
      Assert(Marshal.SizeOf(layout.GetNestedType("EnumTemplate",flags))==72,"FWPM_FILTER_ENUM_TEMPLATE0 x64 ABI");
      Assert(Marshal.OffsetOf(layout.GetNestedType("EnumTemplate",flags),"Flags").ToInt32()==28,"enumeration flags ABI");
      Assert(Marshal.OffsetOf(layout.GetNestedType("EnumTemplate",flags),"Actions").ToInt32()==56,"enumeration action mask ABI");
      Assert(Marshal.OffsetOf(layout.GetNestedType("Filter",flags),"Conditions").ToInt32()==120,"condition pointer ABI");
      var engine=new Fake();var desired=Blocks();Policy.Apply(engine,desired);
      Assert(engine.Commits==1 && engine.Aborts==0 && engine.Rules.Count==3,"apply/readback");
      foreach(var failure in new[]{"add","readback","commit","delete"}){
        var f=new Fake();var old=Blocks();f.Rules.AddRange(old);
        f.FailAdd=failure=="add";f.FailReadback=failure=="readback";f.FailCommit=failure=="commit";f.FailDelete=failure=="delete";
        bool failed=false;try{Policy.Apply(f,Blocks());}catch{failed=true;}
        Assert(failed && f.Aborts==1 && f.Commits==0,"abort on "+failure);Policy.AssertSame(f.Rules.ToArray(),old);
      }
      var after=new Fake{FailAfterCommit=true};bool uncertain=false;try{Policy.Apply(after,Blocks());}catch{uncertain=true;}
      Assert(uncertain && after.Commits==1 && after.Aborts==0,"post-commit mismatch must not report success");
      Policy.Remove(engine);Assert(engine.Rules.Count==0,"owned removal");Policy.Remove(engine);Assert(engine.Rules.Count==0,"idempotent removal");
      var invalid=Blocks().Concat(new[]{new Rule{Id=Guid.NewGuid(),Role="vpn",AppId="AABB",Remote="64:ff9b::/96",Luid="17"}}).ToArray();
      bool rejected=false;try{Policy.Validate(invalid);}catch{rejected=true;}Assert(rejected,"broad NAT64 rejected");
      var incomplete=Blocks().Take(1).ToArray();rejected=false;try{Policy.Validate(incomplete);}catch{rejected=true;}Assert(rejected,"both flow directions required");
      var scoped=Blocks().Concat(new[]{new Rule{Id=Guid.NewGuid(),Role="vpn",AppId="AABB",Remote="64:ff9b::cb00:7101/128",Luid="17"}}).ToArray();
      Policy.Validate(scoped);Assert(scoped[3].Remote=="64:ff9b::cb00:7101/128","exact NAT64 scope");
      var altered=scoped.Select(r=>new Rule{Id=r.Id,Role=r.Role,AppId=r.AppId,Remote=r.Remote,Luid=r.Luid,Inbound=r.Inbound,Boot=r.Boot}).ToArray();altered[3].Luid="18";
      rejected=false;try{Policy.AssertSame(altered,scoped);}catch{rejected=true;}Assert(rejected,"interface read-back mismatch");
      Console.WriteLine("WFP_POLICY_FIXTURES_PASS");
    }
  }
}`
    const root = join(process.cwd(), '.tmp'); mkdirSync(root, { recursive: true })
    const dir = mkdtempSync(join(root, 'wfp-native-')); const path = join(dir, 'harness.ps1')
    try {
      const policy = blocks()
      policy.rules.push({ ...policy.rules[0], id: randomUUID(), role: 'vpn', appId: 'AABB', remote: '2001:db8::1/128', luid: '17' })
      const scripts: string[] = []
      const capture = async (script: string) => { scripts.push(script.replaceAll('$engine=New-Object VPNTE.IPv6.NativeEngine', '$engine=$fixtureEngine')); return { stdout: 'WFP_IPV6_VERIFIED' } }
      await applyWfpIpv6Policy(policy, capture)
      await verifyWfpIpv6Policy(policy, capture)
      const encoded = Buffer.from(source + fixture).toString('base64')
      writeFileSync(path, `$ErrorActionPreference='Stop'\nAdd-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}')))\n[VPNTE.IPv6.Tests.Run]::All()\n$fixtureEngine=New-Object VPNTE.IPv6.Tests.Fake\n${scripts.join('\n')}\nif($fixtureEngine.Rules.Count -ne 4){throw 'Generated rule array incomplete'}\nif($fixtureEngine.Rules[3].Signature -ne $rules[3].Signature){throw 'Generated scope changed'}\nWrite-Output 'WFP_PS_RULES_PASS'`, 'utf8')
      const output = execFileSync(process.env.VPNTE_PWSH || 'powershell.exe', ['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',path], { encoding: 'utf8', windowsHide: true, timeout: 15000 })
      expect(output).toContain('WFP_POLICY_FIXTURES_PASS')
      expect(output).toContain('WFP_PS_RULES_PASS')
    } finally { unlinkSync(path); rmdirSync(dir) }
  }, 20000)
})
