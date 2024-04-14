<#
.SYNOPSIS
Copy an Azure Firewall Policy from one subscription to another subscription

.DESCRIPTION
Copy an Azure Firewall Policy from one subscription to another subscription

.PARAMETER SourceAzFwPolicyID
The Source Azure Firewall Policy ResourceID

.PARAMETER TargetAzFwPolicyID
The Target Azure Firewall Policy ResourceID

.EXAMPLE
Copy-AzFwPolicy.ps1 -SourceAzFwPolicyID "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-source/providers/Microsoft.Network/FirewallPolicies/azfw-source" -TargetAzFwPolicyID "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-target/providers/Microsoft.Network/FirewallPolicies/azfw-target" -IncludeTags

#>

[CmdletBinding()]
# parameters make, mandatory, including includeTags switch
param (
    [Parameter(Mandatory = $true)]
    [Validatescript({
            if (-not ($_ -like "*/providers/Microsoft.Network/FirewallPolicies/*")) {
                throw "The SourceAzFwPolicyID parameter must be a valid Azure Firewall Policy ID."
            }
            return $true
        }
    )]
    [string]$SourceAzFwPolicyID,
    [Parameter(Mandatory = $true)]
    [Validatescript({
            if (-not ($_ -Like "*/providers/Microsoft.Network/FirewallPolicies/*")) {
                throw "The TargetAzFwPolicyID parameter must be a valid Azure Firewall Policy ID."
            }
            return $true
        }
    )]
    [string]$TargetAzFwPolicyID,
    [switch]$IncludeTags
)

# set default error action preference
$ErrorActionPreference = "Stop"

# validate the source and target firewall policy IDs are different
if ($TargetAzFwPolicyID -eq $SourceAzFwPolicyID) {
    Write-Error "The SourceAzFwPolicyID and TargetAzFwPolicyID parameters must be different."
}

if (-not ($TargetAzFwPolicyID.Split("/")[2] -eq $SourceAzFwPolicyID.Split("/")[2])) {
    Write-Error "The SourceAzFwPolicyID and TargetAzFwPolicyID parameters must be in the same subscription."
}

# get the source and target firewall policies
$SourceAzFwPolicy = Get-AzFirewallPolicy -ResourceId $SourceAzFwPolicyID -ErrorAction SilentlyContinue

if ($null -eq $SourceAzFwPolicy) {
    Write-Error "Failed to get Azure Firewall Source Policy: $($SourceAzFwPolicyID)."
}

$TargetAzFwPolicy = Get-AzFirewallPolicy -ResourceId $TargetAzFwPolicyID -ErrorAction SilentlyContinue

if ($null -eq $TargetAzFwPolicy) {
    Write-Error "Failed to get Azure Firewall Target Policy: $($TargetAzFwPolicyID)."
}

# input object for set-azfirewallpolicy
$TargetAzFwPolicy = @{
    ResourceGroupName    = $TargetAzFwPolicy.ResourceGroupName
    Name                 = $TargetAzFwPolicy.Name
    Location             = $TargetAzFwPolicy.Location
    DnsSettings          = $SourceAzFwPolicy.DnsSettings
    ThreatIntelMode      = $SourceAzFwPolicy.ThreatIntelMode
    ThreatIntelWhitelist = $SourceAzFwPolicy.ThreatIntelWhitelist
    ExplicitProxy        = $SourceAzFwPolicy.explicitProxy
    IntrusionDetection   = $SourceAzFwPolicy.IntrusionDetection
    transportSecurity    = $SourceAzFwPolicy.transportSecurity
    Sqlsetting           = $SourceAzFwPolicy.sqlsetting
    BasePolicy           = $SourceAzFwPolicy.BasePolicy
    Snat                 = $SourceAzFwPolicy.Snat
    Tag                  = if ($IncludeTags) { $SourceAzFwPolicy.Tag } else { $null }
}

Write-Host "Getting Rule Collection Groups..."
# for each rule collection group in the source firewall policy
foreach ($SourceAzFwPolicyRuleCollectionGroup in $SourceAzFwPolicy.RuleCollectionGroups) {
    # get the source firewall policy rule collection group
    $RuleCollectionGroup = Get-AzFirewallPolicyRuleCollectionGroup -AzureFirewallPolicyName $SourceAzFwPolicy.Name -ResourceGroupName $SourceAzFwPolicy.ResourceGroupName -Name ($SourceAzFwPolicyRuleCollectionGroup.id).Split("/")[-1]

    Write-Host "Copying Rule Collection Group: $($RuleCollectionGroup.Name)..."
    # set the target firewall policy rule collection group
    $newRuleCollectionGroup = New-AzFirewallPolicyRuleCollectionGroup -Name $RuleCollectionGroup.Name -ResourceGroupName $TargetAzFwPolicy.ResourceGroupName -FirewallPolicyName $TargetAzFwPolicy.Name -Priority $RuleCollectionGroup.Properties.Priority -RuleCollection $RuleCollectionGroup.Properties.RuleCollection
    
    if ($newRuleCollectionGroup) {
        Write-Host "Rule Collection Group $($RuleCollectionGroup.Name) copied successfully." -ForegroundColor Green
    }
    else {
        Write-Error "Failed to copy Rule Collection Group $($RuleCollectionGroup.Name)."
    }

}

Write-Host "Copying Azure Firewall Policy $($SourceAzFwPolicy.Name) to $($TargetAzFwPolicy.Name)..."
# set the target firewall policy
$setPolicy = Set-AzFirewallPolicy -InputObject $TargetAzFwPolicy

if ($setPolicy) {
    Write-Host "Azure Firewall Policy $($SourceAzFwPolicy.Name) copied successfully." -ForegroundColor Green
}
else {
    Write-Error "Failed to copy Azure Firewall Policy $($SourceAzFwPolicy.Name)."
}