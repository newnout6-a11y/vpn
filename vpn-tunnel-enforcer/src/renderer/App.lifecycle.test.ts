// AT-00-008 / AT-07-001: execute actual App callbacks with real Zustand state.
import {readFileSync} from 'node:fs'
import ts from 'typescript'
import {beforeEach, describe, expect, it, vi} from 'vitest'
import {useAppStore} from './store'
import {TunnelStateMachine} from '../main/tunnelStateMachine'
import {ConnectionLifecycle} from '../main/connectionLifecycle'
const source=ts.createSourceFile('App.tsx',readFileSync('src/renderer/App.tsx','utf8'),ts.ScriptTarget.Latest,true,ts.ScriptKind.TSX)
function compile(name:string,deps:Record<string,unknown>) {
  let expression=''
  function visit(node:ts.Node) {
    if(ts.isCallExpression(node)&&ts.isPropertyAccessExpression(node.expression)&&node.expression.name.text===name) expression=node.arguments[0].getText(source)
    if(ts.isFunctionDeclaration(node)&&node.name?.text===name) expression=node.getText(source)+'; return '+name
    ts.forEachChild(node,visit)
  }
  visit(source)
  if(!expression)throw new Error('Missing App body '+name)
  const code=ts.transpileModule(expression.startsWith('async function')?expression:'return '+expression,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText
  return new Function(...Object.keys(deps),code)(...Object.values(deps))
}
beforeEach(()=>useAppStore.setState({tunnelSnapshot:null,connectionBusy:null,connectionCancelling:false,serverSwitchingName:null,publicIp:null,isLeak:false}))
describe('canonical App event handling',()=>{
  it('invalidates firewall evidence during transitions and reads only settled snapshots (AT-00-008 / AT-03-001)',async()=>{
    const stoppingNowRef={current:false},tunEventSeqRef={current:0}
    const onSnapshot=compile('onTunnelStateChanged',{useAppStore,stoppingNowRef,tunEventSeqRef})
    const refresh=vi.spyOn(useAppStore.getState(),'refreshFirewallKillSwitchStatus').mockResolvedValue(undefined)
    let release!:()=>void
    const held=new Promise<void>(resolve=>{release=resolve})
    const os={running:false,pid:null as number|null,softApplied:false}
    const model=new TunnelStateMachine(()=>os,onSnapshot),lane=new ConnectionLifecycle(()=>{},undefined,undefined,model)
    useAppStore.setState({firewallKillSwitchStatus:{state:'verified',cleanupRequired:true,reason:'policy-verified'}})
    try {
      const pending=lane.start(async()=>{await held;os.running=true;os.pid=731;return {success:true}})
      const stale=model.snapshot
      expect(stoppingNowRef.current).toBe(true)
      expect(refresh).not.toHaveBeenCalled()
      expect(useAppStore.getState().firewallKillSwitchStatus).toMatchObject({state:'unknown',reason:'checking'})
      release();await pending
      expect(stoppingNowRef.current).toBe(false)
      expect(refresh).toHaveBeenCalled()
      const calls=refresh.mock.calls.length
      onSnapshot(stale)
      expect(refresh).toHaveBeenCalledTimes(calls)
    } finally {release();refresh.mockRestore()}
  })
  it('keeps renderer Soft mode after a failed refresh with confirmed prior endpoint (AT-00-008)',async()=>{
    const stoppingNowRef={current:false},tunEventSeqRef={current:0}
    const deps={useAppStore,stoppingNowRef,tunEventSeqRef,addLog:vi.fn(),verifyActiveServerCountry:vi.fn(async()=>{})}
    const onSnapshot=compile('onTunnelStateChanged',deps)
    const refresh=vi.spyOn(useAppStore.getState(),'refreshFirewallKillSwitchStatus').mockResolvedValue(undefined)
    try {
      const os={running:false,pid:null,softApplied:false}
      const model=new TunnelStateMachine(()=>os,onSnapshot),lane=new ConnectionLifecycle(()=>{},undefined,undefined,model)
      await lane.start(async()=>{os.softApplied=true;return {success:true}})
      expect(useAppStore.getState().mode).toBe('soft')
      const result=await lane.start(async owner=>{
        expect(model.confirmRetainedSoft(owner.operation.operationId).success).toBe(true)
        return {success:false,error:'refresh failed'}
      },{refreshSoft:true})
      expect(result).toMatchObject({success:false})
      expect(useAppStore.getState()).toMatchObject({mode:'soft',connectionBusy:null,tunRunning:false,
        tunnelSnapshot:{state:'connected',transition:null,operation:{status:'error'}}})
    } finally {refresh.mockRestore()}
  })
  it('accepts leak events after connect, suppresses them during stop, and rejects stale snapshot side effects',async()=>{
    const stoppingNowRef={current:false},tunEventSeqRef={current:0}
    const deps={useAppStore,stoppingNowRef,tunEventSeqRef,addLog:vi.fn(),verifyActiveServerCountry:vi.fn(async()=>{})}
    const onSnapshot=compile('onTunnelStateChanged',deps),onIp=compile('onIpChanged',deps)
    const refresh=vi.spyOn(useAppStore.getState(),'refreshFirewallKillSwitchStatus').mockResolvedValue(undefined)
    const os={running:false,pid:null as number|null,softApplied:false}
    const model=new TunnelStateMachine(()=>os,onSnapshot)
    const lane=new ConnectionLifecycle(()=>{},undefined,undefined,model)
    await lane.start(async()=>{os.running=true;os.pid=731;return {success:true}})
    expect(stoppingNowRef.current).toBe(false)
    onIp({ip:'198.51.100.1',isLeak:true,verdict:'failed'})
    expect(useAppStore.getState().isLeak).toBe(true)
    const stale=model.snapshot
    const stop=lane.stop(async()=>{os.running=false;os.pid=null;return {success:true}})
    expect(stoppingNowRef.current).toBe(true)
    onSnapshot(stale)
    expect(stoppingNowRef.current).toBe(true)
    onIp({ip:'198.51.100.2',isLeak:true,verdict:'failed'})
    expect(useAppStore.getState().publicIp).toBe('198.51.100.1')
    await stop
    expect(stoppingNowRef.current).toBe(false)
    refresh.mockRestore()
  })
  it.each(['disconnected','connected','unknown'] as const)('restores Soft startup through owned API only for %s',async state=>{
    const api={getTunStatus:vi.fn(async()=>({lifecycle:{state,mode:state==='connected'?'soft':null,transition:null}})),startSoftProtection:vi.fn(async()=>({success:true}))}
    const restore=compile('restoreSoftStartup',{window:{electronAPI:api}})
    const task=restore({host:'127.0.0.1',port:8080,type:'http'})
    if(state==='unknown')await expect(task).rejects.toThrow('Сначала восстановите')
    else await task
    expect(api.startSoftProtection).toHaveBeenCalledTimes(state==='unknown'?0:1)
    if(state!=='unknown')expect(api.startSoftProtection).toHaveBeenCalledWith('127.0.0.1:8080','http')
  })
  it.each(['connecting','disconnecting','reconnecting'])('does not refresh Soft during %s',async transition=>{
    const api={getTunStatus:vi.fn(async()=>({lifecycle:{state:'connected',mode:'soft',transition}})),startSoftProtection:vi.fn()}
    const restore=compile('restoreSoftStartup',{window:{electronAPI:api}})
    await expect(restore({host:'127.0.0.1',port:8080,type:'http'})).rejects.toThrow('Сначала восстановите')
    expect(api.startSoftProtection).not.toHaveBeenCalled()
  })
})
