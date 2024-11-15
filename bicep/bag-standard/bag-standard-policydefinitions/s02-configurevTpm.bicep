targetScope = 'managementGroup'

// Custom Policy to remediate a VM with TrustedLaunch security or Standard to enable vTPM 
// tested and works as expected

param policyVersion string
param s02setvtpmeffect string

var policyDefinitionName = 'Custom-Enable-vTPM'
var policyDefinitionDescription = 'BAG-Security Configure supported virtual machines to automatically enable vTPM'

// Azure policy definition
resource policyDef 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: '${policyDefinitionName}-${policyVersion}'
  properties: {
    description: 'Configure supported virtual machines to automatically enable vTPM to facilitate Measured Boot and other OS security features that require a TPM. Once enabled, vTPM can be used to attest boot integrity.'
    displayName: '${policyDefinitionDescription}-${policyVersion}'
    metadata: {
      version: policyVersion
      category: 'Security Center'
    }
    policyType: 'Custom'
    mode: 'Indexed'
    parameters: {
      s02setvtpmeffect: {
        type: 'String'
        metadata: {
          description: 'Enable or disable the execution of the policy'
          displayName: 'Enforce vTPM on supported VMs Effect'
        }
        allowedValues: [
          'DeployIfNotExists'
          'Disabled'
        ]
        defaultValue: s02setvtpmeffect
      }
    }
    policyRule: {
      if: {
        anyOf: [
          // Condition 1: TrustedLaunch VMs must have vTPM enabled
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
                field: 'Microsoft.Compute/virtualMachines/securityProfile.uefiSettings'
                exists: true
              }
              {
                field: 'Microsoft.Compute/virtualMachines/securityProfile.uefiSettings.vTpmEnabled'
                notEquals: 'true'
              }
            ]
          }
          // Condition 2: VMs without a securityProfile must remediate to enable vTPM
          {
            allOf: [
              {
                field: 'type'
                equals: 'Microsoft.Compute/virtualMachines'
              }
              {
                field: 'Microsoft.Compute/virtualMachines/securityProfile'
                exists: false
              }
            ]
          }
        ]
      }
      then: {
        effect: '[parameters(\'s02setvtpmeffect\')]'
        details: {
          type: 'Microsoft.Compute/virtualMachines'
          name: '[field(\'fullName\')]'
          existenceCondition: {
            field: 'Microsoft.Compute/virtualMachines/securityProfile.uefiSettings.vTpmEnabled'
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
                          vTpmEnabled: 'true'
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
  policyDefinitionReferenceId: 'bags02configurevtpm'
  parameters: {
    s02setvtpmeffect: {
      value: '[parameters(\'s02setvtpmeffect\')]'
    }
  }
  groupNames: [
    'S02-Bag-Security'
  ]
}
