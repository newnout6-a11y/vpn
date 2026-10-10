// AT-00-003/007/008, AT-02-005: native effects remain owned through main cleanup.
import {describe,expect,it,vi} from 'vitest'
import {ConnectionLifecycle} from './connectionLifecycle'

function held<T>() {
  let resolve!: (value:T)=>void, reject!: (error:Error)=>void
  const promise=new Promise<T>((yes,no)=>{resolve=yes;reject=no})
  return {promise,resolve,reject}
}

describe('main connection lifecycle ownership',()=>{
  it('keeps preparation deferred through startup and the entire stop effect (AT-02-005)',async()=>{
    const lane=new ConnectionLifecycle(vi.fn()), startup=held<void>(), cleanup=held<void>()
    expect(lane.busy).toBe(false)
    const started=lane.start(async owner=>{await owner.wait(startup.promise);return {success:true}})
    expect(lane.busy).toBe(true)
    const stopped=lane.stop(()=>cleanup.promise)
    startup.resolve()
    expect(await started).toMatchObject({success:false})
    expect(lane.starting).toBe(false)
    expect(lane.busy).toBe(true)
    cleanup.resolve()
    await stopped
    expect(lane.busy).toBe(false)
  })
  it('keeps preparation deferred after lifecycle shutdown (AT-03-007)',async()=>{
    const lane=new ConnectionLifecycle(vi.fn())
    await lane.close()
    expect(lane.busy).toBe(true)
  })
  it('preserves ownership through 100 seeded cancellation handoffs at three boundaries (AT-02-005 subset)',async()=>{
    let seed=0x8090
    for(let iteration=0;iteration<100;iteration++){
      seed=(Math.imul(seed,1664525)+1013904223)>>>0
      const phase=seed%3,lane=new ConnectionLifecycle(vi.fn())
      const gates=Array.from({length:3},()=>held<void>())
      const entered=Array.from({length:3},()=>held<void>())
      const publish=vi.fn(),cleanup=vi.fn(async()=>true)
      for(let index=0;index<phase;index++)gates[index].resolve()
      const started=lane.start(async owner=>{
        for(let index=0;index<3;index++){
          entered[index].resolve()
          await owner.wait(gates[index].promise)
        }
        publish()
        return {success:true}
      })
      await entered[phase].promise
      const stopped=lane.stop(cleanup)
      await Promise.resolve()
      expect(cleanup).not.toHaveBeenCalled()
      for(const gate of gates)gate.resolve()
      expect(await started).toMatchObject({success:false})
      await stopped
      expect(cleanup).toHaveBeenCalledOnce()
      expect(publish).not.toHaveBeenCalled()
      expect(lane.starting).toBe(false)
    }
  })
  it('continues owned cleanup after a cancellation callback throws and permits retry',async()=>{
    const cancel=vi.fn().mockImplementationOnce(()=>{throw new Error('cancel listener failed')})
    const lane=new ConnectionLifecycle(cancel),cleanup=vi.fn(async()=>true)
    await expect(lane.stop(cleanup)).rejects.toThrow('cancel listener failed')
    expect(cleanup).toHaveBeenCalledOnce()
    expect(await lane.start(async()=>({success:true}))).toEqual({success:true})
    expect(await lane.stop(cleanup)).toBe(true)
  })
  it('cancels synchronously but waits for an owned native baseline before stop',async()=>{
    const cancel=vi.fn(),lane=new ConnectionLifecycle(cancel),baseline=held<void>()
    const publish=vi.fn(),cleanup=vi.fn(async()=>({success:true}))
    let signal!:AbortSignal
    const started=lane.start(async owner=>{signal=owner.signal;await owner.wait(baseline.promise);publish();return {success:true}})
    const stopped=lane.stop(cleanup)
    expect(signal.aborted).toBe(true)
    expect(cancel).toHaveBeenCalledOnce()
    await Promise.resolve()
    expect(cleanup).not.toHaveBeenCalled()
    baseline.resolve()
    expect(await started).toEqual({success:false,error:'Запуск отменён'})
    expect(await stopped).toEqual({success:true})
    expect(publish).not.toHaveBeenCalled()
  })
  it('holds admission and native effects even when startup unexpectedly throws',async()=>{
    const lane=new ConnectionLifecycle(vi.fn()),baseline=held<void>(),cleanup=vi.fn(async()=>true)
    const started=lane.start(async owner=>{owner.retain(baseline.promise);throw new Error('startup failure')})
    const observed=started.catch(error=>error)
    await Promise.resolve()
    expect(lane.starting).toBe(true)
    const stopped=lane.stop(cleanup)
    expect((await lane.start(async()=>true)) as any).toMatchObject({success:false})
    expect(cleanup).not.toHaveBeenCalled()
    baseline.resolve()
    expect((await observed).message).toBe('startup failure')
    await stopped
    expect(await lane.start(async()=>({success:true}))).toEqual({success:true})
  })
  it('coalesces 200 stop effects and blocks a simultaneous new startup',async()=>{
    const lane=new ConnectionLifecycle(vi.fn()),done=held<void>(),cleanup=vi.fn(()=>done.promise)
    const requests=Array.from({length:200},()=>lane.stop(cleanup))
    expect(await lane.start(async()=>true)).toMatchObject({success:false})
    await Promise.resolve()
    expect(cleanup).toHaveBeenCalledOnce()
    done.resolve()
    await Promise.all(requests)
  })
  it('closes admission permanently and waits for startup on shutdown',async()=>{
    const lane=new ConnectionLifecycle(vi.fn()),native=held<void>()
    const started=lane.start(async owner=>{await owner.wait(native.promise);return {success:true}})
    const finished=vi.fn(),closing=lane.close().then(finished)
    expect(await lane.start(async()=>true)).toMatchObject({success:false})
    expect(finished).not.toHaveBeenCalled()
    native.resolve()
    expect(await started).toMatchObject({success:false})
    await closing
    expect(finished).toHaveBeenCalledOnce()
  })
  it('consumes a late rejected native effect and releases the startup lease',async()=>{
    const lane=new ConnectionLifecycle(vi.fn()),native=held<void>()
    const started=lane.start(async owner=>{owner.retain(native.promise);return {success:true}})
    const stopped=lane.stop(async()=>true)
    native.reject(new Error('native failed'))
    expect(await started).toMatchObject({success:false})
    await stopped
    expect(lane.starting).toBe(false)
  })
})
