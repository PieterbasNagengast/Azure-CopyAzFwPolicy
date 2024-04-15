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

$sourceSubscriptionId = $SourceAzFwPolicyID.Split("/")[2]
$targetSubscriptionId = $TargetAzFwPolicyID.Split("/")[2]

# validate the source and target firewall policy IDs are different
if ($TargetAzFwPolicyID -eq $SourceAzFwPolicyID) {
    Write-Error "The SourceAzFwPolicyID and TargetAzFwPolicyID parameters must be different."
}

# validate if we need to swtich context to source firewall policy subscription
Write-Host "Checking current context..."
$CurrentAzContext = Get-AzContext

if (!$CurrentAzContext) {
    Write-Error "Failed to get current Azure context."
}

if ($CurrentAzContext.Subscription.Id -ne $sourceSubscriptionId) {
    $sourceSubscription = Get-AzSubscription -SubscriptionId $sourceSubscriptionId
    write-host "Switching to source subscription: $($sourceSubscription.Name)"
    $CurrentAzContext = Set-AzContext -Subscription $sourceSubscription
}
else {
    Write-Host "Current context is already in the correct subscription: $($CurrentAzContext.Subscription.Name)" -ForegroundColor Green
}

# get the source and target firewall policies
Write-Verbose "Getting Azure Firewall Policy: $($SourceAzFwPolicyID)"
$SourceAzFwPolicy = Get-AzFirewallPolicy -ResourceId $SourceAzFwPolicyID -ErrorAction SilentlyContinue

if ($null -eq $SourceAzFwPolicy) {
    Write-Error "Failed to get Azure Firewall Source Policy: $($SourceAzFwPolicyID)."
}

if ($CurrentAzContext.Subscription.Id -ne $targetSubscriptionId) {
    $targetSubscription = Get-AzSubscription -SubscriptionId $targetSubscriptionId
    write-host "Switching to target subscription: $($targetSubscription.Name)"
    $CurrentAzContext = Set-AzContext -Subscription $targetSubscription
}
else {
    Write-Host "Current context is already in the correct subscription: $($CurrentAzContext.Subscription.Name)" -ForegroundColor Green
}

Write-Verbose "Getting Azure Firewall Policy: $($TargetAzFwPolicyID)"
$TargetAzFwPolicy = Get-AzFirewallPolicy -ResourceId $TargetAzFwPolicyID -ErrorAction SilentlyContinue

if ($null -eq $TargetAzFwPolicy) {
    Write-Error "Failed to get Azure Firewall Target Policy: $($TargetAzFwPolicyID)."
}

Write-Verbose "Source Azure Firewall Policy SKU: $($SourceAzFwPolicy.Sku.Tier)"
Write-Verbose "Target Azure Firewall Policy SKU: $($TargetAzFwPolicy.Sku.Tier)"

# check if both source and target firewall policies have the same sku
if ($SourceAzFwPolicy.Sku.Tier -ne $TargetAzFwPolicy.Sku.Tier) {
    Write-Error "The Source and Target Azure Firewall Policies must have the same SKU."
}
else {
    Write-Host "Source and Target Azure Firewall Policies have the same SKU: $($SourceAzFwPolicy.Sku.Tier)" -ForegroundColor Green
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

Write-Verbose ($TargetAzFwPolicy | ConvertTo-Json -Depth 100)

Write-Host "Copying Azure Firewall Policy $($SourceAzFwPolicy.Name) to $($TargetAzFwPolicy.Name)..."
# set the target firewall policy
$setPolicy = Set-AzFirewallPolicy -InputObject $TargetAzFwPolicy

if ($setPolicy) {
    Write-Host "Azure Firewall Policy $($SourceAzFwPolicy.Name) copied successfully." -ForegroundColor Green
}
else {
    Write-Error "Failed to copy Azure Firewall Policy $($SourceAzFwPolicy.Name)."
}

Write-Host "Getting Rule Collection Groups..."
# for each rule collection group in the source firewall policy
foreach ($SourceAzFwPolicyRuleCollectionGroup in $SourceAzFwPolicy.RuleCollectionGroups) {
    # get the source firewall policy rule collection group
    $RuleCollectionGroup = Get-AzFirewallPolicyRuleCollectionGroup -AzureFirewallPolicyName $SourceAzFwPolicy.Name -ResourceGroupName $SourceAzFwPolicy.ResourceGroupName -Name ($SourceAzFwPolicyRuleCollectionGroup.id).Split("/")[-1]

    Write-Host "Copying Rule Collection Group: $($RuleCollectionGroup.Name)..."
    write-verbose "Copying Rule Collection(s): $($RuleCollectionGroup.Properties.RuleCollection.name) with a total of $(($RuleCollectionGroup.Properties.RuleCollection.rules).Count) rule(s)"
    # set the target firewall policy rule collection group
    $newRuleCollectionGroup = New-AzFirewallPolicyRuleCollectionGroup -Name $RuleCollectionGroup.Name -ResourceGroupName $TargetAzFwPolicy.ResourceGroupName -FirewallPolicyName $TargetAzFwPolicy.Name -Priority $RuleCollectionGroup.Properties.Priority -RuleCollection $RuleCollectionGroup.Properties.RuleCollection
    
    if ($newRuleCollectionGroup) {
        Write-Host "Rule Collection Group $($RuleCollectionGroup.Name) copied successfully." -ForegroundColor Green
    }
    else {
        Write-Error "Failed to copy Rule Collection Group $($RuleCollectionGroup.Name)."
    }

}

