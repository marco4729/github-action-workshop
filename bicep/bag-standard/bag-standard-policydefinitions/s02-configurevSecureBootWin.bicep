targetScope = 'managementGroup'

// Custom policy to enable Secure Boot on supported Windows virtual machines - tested:

param policyVersion string
param s02setsecurebooteffect string

var policyDefinitionName = 'Custom-Enable-SecureBoot'
var policyDefinitionDescription = 'BAG-Security Configure supported Windows virtual machines to automatically enable Secure Boot'

// Azure policy definition
resource policyDef 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: '${policyDefinitionName}-${policyVersion}'
  properties: {
    description: 'Configure supported Windows virtual machines to automatically enable Secure Boot to mitigate against malicious and unauthorized changes to the boot chain. Once enabled, only trusted bootloaders, kernel, and kernel drivers will be allowed to run.'
    displayName: '${policyDefinitionDescription}-${policyVersion}'
    metadata: {
      version: policyVersion
      category: 'Security Center'
      preview: true
    }
    policyType: 'Custom'
    mode: 'Indexed'
    parameters: {
      s02setsecurebooteffect: {
        type: 'String'
        metadata: {
          description: 'Enable or disable the execution of the policy'
          displayName: 'Effect'
        }
        allowedValues: [
          'DeployIfNotExists'
          'Disabled'
        ]
        defaultValue: s02setsecurebooteffect
      }
    }
    policyRule: {
      if: {
        anyOf: [
          // Condition 1: TrustedLaunch Windows VMs with Secure Boot disabled
          {
            allOf: [
              {
                field: 'type'
                equals: 'Microsoft.Compute/virtualMachines'
              }
              {
                field: 'Microsoft.Compute/virtualMachines/securityProfile.securityType'
                equals: 'TrustedLaunch'
              }
              {
                field: 'Microsoft.Compute/virtualMachines/securityProfile.uefiSettings.secureBootEnabled'
                notEquals: 'true'
              }
              {
                anyOf: [
                  {
                    field: 'Microsoft.Compute/virtualMachines/storageProfile.imageReference.offer'
                    like: 'windows*'
                  }
                  {
                    field: 'Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType'
                    equals: 'Windows'
                  }
                ]
              }
            ]
          }
          // Condition 2: VMs without a securityProfile must remediate to enable Secure Boot
          {
            allOf: [
              {
                field: 'type'
                equals: 'Microsoft.Compute/virtualMachines'
              }
              {
                anyOf: [
                  {
                    field: 'Microsoft.Compute/virtualMachines/storageProfile.imageReference.offer'
                    like: 'windows*'
                  }
                  {
                    field: 'Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType'
                    equals: 'Windows'
                  }
                ]
              }
            ]
          }
        ]
      }
      then: {
        effect: '[parameters(\'s02setsecurebooteffect\')]'
        details: {
          type: 'Microsoft.Compute/virtualMachines'
          name: '[field(\'fullName\')]'
          existenceCondition: {
            field: 'Microsoft.Compute/virtualMachines/securityProfile.uefiSettings.secureBootEnabled'
            equals: 'true'
          }
          roleDefinitionIds: [
            '/providers/microsoft.authorization/roleDefinitions/9980e02c-c2be-4d73-94e8-173b1dc7cf3c'
          ]
          deployment: {
            properties: {
              mode: 'incremental'
              parameters: {
                vmName: {
                  value: '[field(\'name\')]'
                }
                location: {
                  value: '[field(\'location\')]'
                }
              }
              template: {
                '$schema': 'http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#'
                contentVersion: '1.0.0.0'
                parameters: {
                  vmName: {
                    type: 'string'
                  }
                  location: {
                    type: 'string'
                  }
                }
                resources: [
                  {
                    name: '[parameters(\'vmName\')]'
                    location: '[parameters(\'location\')]'
                    type: 'Microsoft.Compute/virtualMachines'
                    apiVersion: '2024-07-01'
                    properties: {
                      securityProfile: {
                        uefiSettings: {
                          secureBootEnabled: 'true'
                        }
                        securityType: 'TrustedLaunch'
                      }
                    }
                  }
                ]
              }
            }
          }
        }
      }
    }
  }
}

////////////////////////////////
// Output Area
////////////////////////////////

output policyParameterObject object = {
  policyDefinitionId: policyDef.id
  policyDefinitionReferenceId: 'bags02configureSecureBoot'
  parameters: {
    s02setsecurebooteffect: {
      value: '[parameters(\'s02setsecurebooteffect\')]'
    }
  }
  groupNames: [
    'S02-Bag-Security'
  ]
}
