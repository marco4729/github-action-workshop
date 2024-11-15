targetScope = 'managementGroup'

/* Custom Policy / Tested:
- Won't allow the creation of a VM unless it has TrustedLaunch or ConfidentialVM security type and vTpm and SecureBoot enabled
- VMs will be non-compliant unless the state is met
*/

param policyVersion string
param s02shouldTrustedLaunch string

var policyDefinitionName = 'Ensure-TrustedLaunch-plus'
var policyDefinitionDescription = 'BAG-Security Ensure VMs have TrustedLaunch or ConfidentialVM launch with vTpm and SecureBoot enabled'

// Azure policy definition
resource policyDef 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: '${policyDefinitionName}-${policyVersion}'
  properties: {
    description: 'Enable TrustedLaunch on Virtual Machine for enhanced security, use VM SKU (Gen 2) that supports TrustedLaunch. To learn more about TrustedLaunch, visit https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch'
    displayName: '${policyDefinitionDescription}-${policyVersion}'
    metadata: {
      version: policyVersion
      category: 'Trusted Launch'
    }
    policyType: 'Custom'
    mode: 'Indexed'
    parameters: {
      s02shouldTrustedLaunch: {
        type: 'String'
        metadata: {
          description: 'Enable or disable the execution of the policy'
          displayName: 'Effect'
        }
        allowedValues: [
          'Audit'
          'Disabled'
          'Deny'
        ]
        defaultValue: s02shouldTrustedLaunch
      }
    }
    policyRule: {
      if: {
        anyOf: [
          // Condition: `secureBootEnabled` is not true
          {
            allOf: [
              {
                field: 'type'
                equals: 'Microsoft.Compute/virtualMachines'
              }
              {
                field: 'Microsoft.Compute/virtualMachines/securityProfile.uefiSettings.secureBootEnabled'
                notEquals: 'true'
              }
            ]
          }
          // Condition: `vTpmEnabled` is not true
          {
            allOf: [
              {
                field: 'type'
                equals: 'Microsoft.Compute/virtualMachines'
              }
              {
                field: 'Microsoft.Compute/virtualMachines/securityProfile.uefiSettings.vTpmEnabled'
                notEquals: 'true'
              }
            ]
          }
          // Condition: `securityType` is not TrustedLaunch or ConfidentialVM
          {
            allOf: [
              {
                field: 'type'
                equals: 'Microsoft.Compute/virtualMachines'
              }
              {
                not: {
                  anyOf: [
                    {
                      field: 'Microsoft.Compute/virtualMachines/securityProfile.securityType'
                      equals: 'TrustedLaunch'
                    }
                    {
                      field: 'Microsoft.Compute/virtualMachines/securityProfile.securityType'
                      equals: 'ConfidentialVM'
                    }
                  ]
                }
              }
            ]
          }
        ]
      }
      then: {
        effect: '[parameters(\'s02shouldTrustedLaunch\')]'
      }
    }
  }
}    

////////////////////////////////
// Output Area
////////////////////////////////

output policyParameterObject object = {
  policyDefinitionId: policyDef.id
  policyDefinitionReferenceId: 'bags02shouldTrustedLaunch'
  parameters: {
    s02shouldTrustedLaunch: {
      value: '[parameters(\'s02shouldTrustedLaunch\')]'
    }
  }
  groupNames: [
    'S02-Bag-Security'
  ]
}
