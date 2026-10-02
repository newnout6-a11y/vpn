// Native rule operations only. Profile snapshot/restore stays in NetSecurity,
// including NotConfigured and the existing durable recovery transaction.
export const FIREWALL_RULES_API_PS = `
# VPNTE_RULE_API_BEGIN
$vpnteRuleContext = @{policy=$null}
function Get-VpnteFirewallPolicy {
  # Lazy acquisition lets independent profile rollback steps run even when
  # the rule API is unavailable. Cache the COM handle, never enumerated rules.
  if($null -eq $vpnteRuleContext.policy){$vpnteRuleContext.policy=New-Object -ComObject HNetCfg.FwPolicy2}
  if($null -eq $vpnteRuleContext.policy){throw 'Firewall policy unavailable'}
  $vpnteRuleContext.policy
}
function Get-VpnteFirewallRuleNames {
  [CmdletBinding()] param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$DisplayName)
  foreach($pattern in $DisplayName){if(-not $pattern.StartsWith('VPNTE-killswitch',[StringComparison]::Ordinal)){throw 'Foreign firewall query refused'}}
  $policy=Get-VpnteFirewallPolicy
  $rules=$policy.Rules
  if($null -eq $rules){throw 'Firewall rules unavailable'}
  # A fresh enumeration on every call; never cache a successful ownership proof.
  foreach($rule in $rules){
    $name=[string]$rule.Name
    # Keep legacy names visible to recovery probes, just as the prior prefix
    # query did. New rules have stricter input validation below.
    if(-not $name.StartsWith('VPNTE-killswitch',[StringComparison]::OrdinalIgnoreCase)){continue}
    foreach($pattern in $DisplayName){if($name -like $pattern){$name;break}}
  }
}
function Remove-VpnteFirewallRules {
  [CmdletBinding()] param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$DisplayName)
  $names=@(Get-VpnteFirewallRuleNames -DisplayName $DisplayName -ErrorAction Stop)
  $policy=Get-VpnteFirewallPolicy
  foreach($name in $names){$policy.Rules.Remove($name)}
  if(@(Get-VpnteFirewallRuleNames -DisplayName $DisplayName -ErrorAction Stop).Count){throw 'VPNTE rule removal not verified'}
}
function New-VpnteFirewallRule {
  [CmdletBinding()] param([string]$DisplayName,[string]$Description,[string]$Direction,[string]$Action,
    [string]$Profile,[string]$Enabled,[string]$Program,[string[]]$RemoteAddress,[string[]]$LocalAddress,
    [string[]]$InterfaceAlias,[string]$Protocol,[string[]]$RemotePort)
  if($DisplayName -notmatch '^VPNTE-killswitch-[a-zA-Z0-9_-]{1,100}$' -or $Action -ne 'Allow' -or
    $Profile -ne 'Any' -or $Direction -notin @('Inbound','Outbound') -or $Enabled -notin @('True','False')){throw 'Invalid VPNTE firewall rule'}
  if($Protocol -and $Protocol -notin @('TCP','UDP')){throw 'Unsupported VPNTE firewall protocol'}
  if($RemotePort -and -not $Protocol){throw 'VPNTE ports require TCP or UDP'}
  $rule=New-Object -ComObject HNetCfg.FwRule
  $rule.Name=$DisplayName
  $rule.Description=$Description
  $rule.Direction=if($Direction -eq 'Outbound'){2}else{1}
  $rule.Action=1
  $rule.Profiles=2147483647
  $rule.Enabled=$Enabled -eq 'True'
  $rule.EdgeTraversal=$false
  # Protocol must precede port properties (Windows validates each assignment).
  $rule.Protocol=if($Protocol -eq 'TCP'){6}elseif($Protocol -eq 'UDP'){17}else{256}
  if($RemotePort){$rule.RemotePorts=$RemotePort -join ','}
  if($Program){$rule.ApplicationName=$Program}
  if($RemoteAddress){$rule.RemoteAddresses=$RemoteAddress -join ','}
  if($LocalAddress){$rule.LocalAddresses=$LocalAddress -join ','}
  # The Automation property needs SAFEARRAY(VARIANT), not SAFEARRAY(BSTR).
  if($InterfaceAlias){
    # Casting string[] to object[] can retain the original array through .NET
    # covariance in the legacy Windows host. Allocate the VARIANT array explicitly.
    $interfaces=[Array]::CreateInstance([object],$InterfaceAlias.Count)
    for($i=0;$i -lt $InterfaceAlias.Count;$i++){$interfaces[$i]=[string]$InterfaceAlias[$i]}
    $rule.Interfaces=$interfaces
  }
  $policy=Get-VpnteFirewallPolicy
  $policy.Rules.Add($rule)
}
# VPNTE_RULE_API_END
`

export function withFirewallRulesApi(script: string): string {
  return /\b(?:Get-VpnteFirewallRuleNames|New-VpnteFirewallRule|Remove-VpnteFirewallRules)\b/.test(script)
    ? FIREWALL_RULES_API_PS + script : script
}
