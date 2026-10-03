// Transaction tests use in-memory NetSecurity fixtures for their OS boundary.
// Direct COM primitives have separate executable tests in firewallRulesApi.test.
export const FIREWALL_RULES_BOUNDARY_FIXTURE_PS = `
function New-VpnteFirewallRule {
 param($DisplayName,$Description,$Direction,$Action,$Profile,$Enabled,$Program,$RemoteAddress,$LocalAddress,$InterfaceAlias,$Protocol,$RemotePort)
 New-NetFirewallRule @PSBoundParameters
}
function Get-VpnteFirewallRuleNames {
 param([string[]]$DisplayName)
 Get-NetFirewallRule -DisplayName $DisplayName | ForEach-Object { [string]$_.DisplayName }
}
function Remove-VpnteFirewallRules {
 param([string[]]$DisplayName)
 Get-NetFirewallRule -DisplayName $DisplayName | Remove-NetFirewallRule
 if(@(Get-NetFirewallRule -DisplayName $DisplayName).Count){throw 'VPNTE rule removal not verified'}
}
`
