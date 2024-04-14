# Azure-CopyAzFwPolicy

Copy Azure Firewall Policy

## Description

This script copies an Azure Firewall Policy from one subscription to another. The script will copy the rules, rule collections, and rule groups from the source policy to the destination policy. The script will also copy the Azure Firewall Policy's name, description, and priority.

## Prerequisites

The script requires the following:

- Azure PowerShell Az module
- An Azure subscription
- The source and destination Azure Firewall Policies must be in the same subscription

## Usage

```powershell
.\Copy-AzFwPolicy.ps1 -SourceAzFwPolicyID "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-source/providers/Microsoft.Network/FirewallPolicies/azfw-source" -TargetAzFwPolicyID "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-target/providers/Microsoft.Network/FirewallPolicies/azfw-target" -IncludeTags

```