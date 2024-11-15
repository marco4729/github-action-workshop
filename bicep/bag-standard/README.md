# Baggenstos Standard Policies

**Creation Date:** 29/08/2024  
**Author:** Marco Florez  
**Description:** Deployment of Custom Policies in a  Initiative which represent the standard and security policies of baggenstos.
**Scope:** ManagementGroup

## Dependencies
| Name                           | Required | Description                                                                                     |
| :----------------------------: | :------: | :---------------------------------------------------------------------------------------------- |
| Permissions                    | Yes      | Required. Tenant Owner (for MG Scope)                                                     |
| Permissions                    | Yes      | Required. Subscription Owner (for Subscription Scope)                                     |


## Parameter for main.bicep 
| Name                        | Type   | Required | Description                                                                                      |
|-----------------------------|--------|----------|--------------------------------------------------------------------------------------------------|
| deployPolicyGroup           | object | No       | Has defaults: Can control wheter s01 and/or s02 policies are deployed                            |
| policysetValues             | object | No       | Has defaults: Naming for resources and versioning                                                |
| s01allowedLocations         |array | Yes      | Array of allowed locations. (global is already exluded in policy)                                |
| s01enforcedTags             | object | No       | Has defaults: Naming for 4 Tags which will be enforced and inherited (have to be 4)              |
| s01effect                   | string | No       | Has defaults: Effect for the s01 policies, either 'deny' or 'audit'                              |
| s02shouldTrustedLaunch      | string | No       | Has defaults: Effect for the s02 policy, either 'deny', 'audit' or 'disabled'                     |

## Notes
### Policies S01
S01-Bag-General
- s01-allowedLocations.bicep 
  - Locations can be set in array s01allowedLocations (deny)
  - Locations can be changed after deployment in Initiative
  - The policy excludes resources which have the location set to "global"
- s01-enforceTagsOnRg.bicep (Audit/Deny/Disabled)
  - 4 Tags are enforced on RG level.
  - Changing Tags over the initiative can be done, but is not recommended due to the fact, that inherritTags policy will create paramTag Names which cannot be changed, so changed enforced values become "unclear"
- s01-inheritTag.bicep (modify)
  - InheritTag -> Creates 4 Policies for every Tag individually -> this allows that only that specific tag gets inherited - if for example 2 out 4 "enforced" tags are already correctly set.
  - InheritTag -> looped with value from s01enforcedTags for paramter 'tag'
  - InheritTag Policies uses the name of the Tag for the parameterName. Meaning after the bicep deployment should not be changed to keep it "clear".

### Policies S02
S02-Bag-Security
- s02-shouldTrustedLaunch.bicep
  - Policy to make sure if the security mode is set to thrustedLaunch or confidential and SecureBoot + vTpm is enabled on either Linux or Windows Machines.
  - Effect is set to either 'deny', 'audit' or 'disabled'
  - fortinet OS is exluded in the policy
- s02-configureSecureBootLinux.bicep
  - Policy to enable SecureBoot on supported Linux Machines.
  - deployItNotExist - only works when VM is shut down. Won't change setting on newly deployed VM
  - fortinet OS is exluded in the policy
- s02-configureSecureBootWin.bicep 
  - Policy to enable SecureBoot on supported Windows Machines.
  - deployItNotExist - only works when VM is shut down. Won't change setting on newly deployed VM
- s02-configurevTpm.bicep
  - Policy to enable (deployIfNotExist) vTpm on either Linux or Windows Machines.
  - deployItNotExist - only works when VM is shut down. Won't change setting on newly deployed VM
  - fortinet OS is exluded in the policy

### Initiative
bag-standard-policyset.bicep
- Creates the policySet and policyAssignment. Adds the Contributor Role to the systemAssignedIdentity for the assignment.
