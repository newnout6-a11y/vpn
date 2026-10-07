# AT-03-001/007/010/012: real BFE ABI/read-back; never commits traffic filters.
param([string]$OutputPath)
$ErrorActionPreference='Stop'
$result=@{ok=$false;aborted=$false}
try {
  $root=Split-Path $PSScriptRoot -Parent
  $source=(Get-Content -LiteralPath (Join-Path $root 'resources/vpnte-wfp-ipv6.cs') -Raw).Replace("`r`n","`n")
  $main=Get-Content -LiteralPath (Join-Path $root 'src/main/wfpIpv6.ts') -Raw
  $expected=[regex]::Match($main,"WFP_SOURCE_SHA256 = '([a-f0-9]{64})'").Groups[1].Value
  $sha=[Security.Cryptography.SHA256]::Create()
  try{$hash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($source)))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  if($hash -ne $expected){throw 'WFP source integrity mismatch'}
  $fixture=@'
namespace VPNTE.IPv6.Tests {
  public sealed class RollbackEngine : IEngine {
    public readonly NativeEngine Native=new NativeEngine();
    public bool Aborted;
    public void Begin(){Native.Begin();} public void Commit(){} public void Abort(){Native.Abort();Aborted=true;}
    // ABI tests remain inside an aborted transaction even on hosts with a
    // conflicting third-party VPN. Production Apply still checks priority.
    public void EnsureSublayer(){typeof(NativeEngine).GetMethod("CheckSublayer",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Instance).Invoke(Native,new object[]{true});}
    public Rule[] ReadOwned(){return Native.ReadOwned();}
    public void Add(Rule r){Native.Add(r);} public void Delete(Guid id){Native.Delete(id);} public void Dispose(){Native.Dispose();}
  }
  public static class NativeSmoke {
    public static int Run(RollbackEngine engine,string app,string luid){
      var rules=new List<Rule>();
      foreach(var role in new[]{"block","lan","tun","vpn","exception-app","exception-ip"}) {
        var remotes=role=="lan" ? new[]{"::1/128","fc00::/7","fe80::/10","ff00::/8"} : new[]{role=="vpn" || role=="exception-ip" ? "2001:db8::1/128" : ""};
        foreach(var remote in remotes) foreach(var direction in new[]{0,1,2}) {
          if(direction==2 && role!="block" && role!="lan")continue;
          rules.Add(new Rule{Id=Guid.NewGuid(),Role=role,Remote=remote,AppId=role=="vpn" || role=="exception-app" ? app : "",Luid=role=="vpn" || role=="tun" ? luid : "",Inbound=direction==1,Boot=direction==2});
        }
      }
      Policy.Apply(engine,rules.ToArray()); // Commit is deliberately a no-op.
      Policy.AssertSame(engine.ReadOwned(),rules.ToArray());
      return rules.Count;
    }
  }
}
'@
  Add-Type -TypeDefinition ($source+$fixture)
  $adapter=Get-NetAdapter -Physical -ErrorAction Stop | Where-Object Status -eq 'Up' | Select-Object -First 1
  if(-not $adapter){throw 'No physical interface for native smoke test'}
  $appId=[VPNTE.IPv6.NativeEngine]::AppId((Get-Process -Id $PID).Path)
  $luid=[VPNTE.IPv6.NativeEngine]::InterfaceLuid([string]$adapter.InterfaceGuid)
  $engine=New-Object VPNTE.IPv6.Tests.RollbackEngine
  try {
    # Run() owns Begin(); even failed apply calls Abort. A second Abort can
    # report NO_TXN_IN_PROGRESS, so success tracks the pending transaction.
    $result.rules=[VPNTE.IPv6.Tests.NativeSmoke]::Run($engine,$appId,$luid)
    try {$engine.Native.VerifyPriority();$result.priority='verified'} catch {
      if($_.Exception.ToString() -notlike '*IPv6 WFP priority conflict*'){throw}
      $result.priority='conflict';$result.conflict=$_.Exception.Message
    }
    $engine.Abort();$result.aborted=$true
    $result.ok=$true
  } finally {
    try {if(-not $engine.Aborted){$engine.Abort()};$result.aborted=$engine.Aborted} finally {$engine.Dispose()}
  }
} catch {$result.error=$_.Exception.ToString()}
$json=$result | ConvertTo-Json -Depth 5
if($OutputPath){$json | Set-Content -LiteralPath $OutputPath -Encoding UTF8}
$json
if(-not $result.ok){exit 1}
