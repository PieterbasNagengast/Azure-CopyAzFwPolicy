# Description: Copy an Azure Firewall Policy from one subscription to another subscription

# enable command line binding
[CmdletBinding()]
# commandline parameters make them mandatory, including includeTags toggle
param (
    [Parameter(Mandatory = $true)]
    [string]$SourceAzFwPolicyID,
    [Parameter(Mandatory = $true)]
    [string]$TargetAzFwPolicyID
)
    

# get the source and target firewall policies
$SourceAzFwPolicy = Get-AzFirewallPolicy -ResourceId $SourceAzFwPolicyID
$TargetAzFwPolicy = Get-AzFirewallPolicy -ResourceId $TargetAzFwPolicyID

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
}

# for each rule collection group in the source firewall policy
foreach ($SourceAzFwPolicyRuleCollectionGroup in $SourceAzFwPolicy.RuleCollectionGroups) {
    # get the source firewall policy rule collection group
    $RuleCollectionGroup = Get-AzFirewallPolicyRuleCollectionGroup -AzureFirewallPolicyName $SourceAzFwPolicy.Name -ResourceGroupName $SourceAzFwPolicy.ResourceGroupName -Name ($SourceAzFwPolicyRuleCollectionGroup.id).Split("/")[-1]

    # set the target firewall policy rule collection group
    New-AzFirewallPolicyRuleCollectionGroup -Name $RuleCollectionGroup.Name -ResourceGroupName $TargetAzFwPolicy.ResourceGroupName -FirewallPolicyName $TargetAzFwPolicy.Name -Priority $RuleCollectionGroup.Properties.Priority -RuleCollection $RuleCollectionGroup.Properties.RuleCollection
    
}

# set the target firewall policy
Set-AzFirewallPolicy -InputObject $TargetAzFwPolicy