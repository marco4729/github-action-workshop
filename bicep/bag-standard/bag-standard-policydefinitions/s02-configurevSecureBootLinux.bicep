targetScope = 'managementGroup'

// Custom policy to enable Secure Boot on supported Linux virtual machines

param policyVersion string
param s02setsecurebooteffect string

var policyDefinitionName = 'Custom-Enable-SecureBoot-Linux'
var policyDefinitionDescription = 'BAG-Security Configure supported Linux virtual machines to automatically enable Secure Boot'

// Azure policy definition
resource policyDef 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: '${policyDefinitionName}-${policyVersion}'
  properties: {
    description: 'Configure supported Linux virtual machines to automatically enable Secure Boot to mitigate against malicious and unauthorized changes to the boot chain. Once enabled, only trusted bootloaders, kernel and kernel drivers will be allowed to run.'
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
        allOf: [
          {
            field: 'type'
            equals: 'Microsoft.Compute/virtualMachines'
          }
          {
            anyOf: [
              {
                allOf: [
                  {
                    field: 'Microsoft.Compute/virtualMachines/securityProfile.securityType'
                    equals: 'TrustedLaunch'
                  }
                  {
                    field: 'Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType'
                    like: 'Linux*'
                  }
                  {
                    field: 'Microsoft.Compute/virtualMachines/securityProfile.uefiSettings.secureBootEnabled'
                    notEquals: 'true'
                  }
                ]
              }
              {
                allOf: [
                  {
                    field: 'Microsoft.Compute/virtualMachines/securityProfile.securityType'
                    exists: false
                  }
                  {
                    field: 'Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType'
                    like: 'Linux*'
                  }
                  {
                    field: 'Microsoft.Compute/virtualMachines/securityProfile.uefiSettings.secureBootEnabled'
                    notEquals: 'true'
                  }
                ]
              }
            ]
          }
          {
            anyOf: [
              {
                allOf: [
                  {
                    field: 'Microsoft.Compute/imagePublisher'
                    equals: 'Canonical'
                  }
                  {
                    field: 'Microsoft.Compute/imageOffer'
                    equals: 'UbuntuServer'
                  }
                  {
                    field: 'Microsoft.Compute/imageSku'
                    like: '18_04-lts-gen2'
                  }
                ]
              }
              {
                allOf: [
                  {
                    field: 'Microsoft.Compute/imagePublisher'
                    equals: 'Canonical'
                  }
                  {
                    field: 'Microsoft.Compute/imageOffer'
                    equals: '0001-com-ubuntu-server-focal'
                  }
                  {
                    field: 'Microsoft.Compute/imageSku'
                    like: '20_04-lts-gen2'
                  }
                ]
              }
              {
                allOf: [
                  {
                    field: 'Microsoft.Compute/imagePublisher'
                    equals: 'RedHat'
                  }
                  {
                    field: 'Microsoft.Compute/imageOffer'
                    equals: 'RHEL'
                  }
                  {
                    field: 'Microsoft.Compute/imageSku'
                    like: '83-gen2'
                  }
                ]
              }
              {
                allOf: [
                  {
                    field: 'Microsoft.Compute/imagePublisher'
                    equals: 'SUSE'
                  }
                  {
                    field: 'Microsoft.Compute/imageOffer'
                    equals: 'SLES-15-SP2'
                  }
                  {
                    field: 'Microsoft.Compute/imageSku'
                    like: 'gen2'
                  }
                ]
              }
              {
                allOf: [
                  {
                    field: 'Microsoft.Compute/imagePublisher'
                    equals: 'OpenLogic'
                  }
                  {
                    field: 'Microsoft.Compute/imageOffer'
                    equals: 'CENTOS'
                  }
                  {
                    field: 'Microsoft.Compute/imageSku'
                    equals: '8_3-gen2'
                  }
                ]
              }
              {
                allOf: [
                  {
                    field: 'Microsoft.Compute/imagePublisher'
                    equals: 'Oracle'
                  }
                  {
                    field: 'Microsoft.Compute/imageOffer'
                    equals: 'Oracle-Linux'
                  }
                  {
                    field: 'Microsoft.Compute/imageSku'
                    equals: 'ol83-lvm-gen2'
                  }
                ]
              }
              {
                allOf: [
                  {
                    field: 'Microsoft.Compute/imagePublisher'
                    equals: 'microsoftcblmariner'
                  }
                  {
                    field: 'Microsoft.Compute/imageOffer'
                    equals: 'cbl-mariner'
                  }
                  {
                    field: 'Microsoft.Compute/imageSku'
                    equals: '1-gen2'
                  }
                ]
              }
              {
                allOf: [
                  {
                    field: 'Microsoft.Compute/imagePublisher'
                    equals: 'debian'
                  }
                  {
                    field: 'Microsoft.Compute/imageOffer'
                    equals: 'debian-11'
                  }
                  {
                    field: 'Microsoft.Compute/imageSku'
                    equals: '11-gen2'
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
  policyDefinitionReferenceId: 'bags02configureSecureBootLinux'
  parameters: {
    s02setsecurebooteffect: {
      value: '[parameters(\'s02setsecurebooteffect\')]'
    }
  }
  groupNames: [
    'S02-Bag-Security'
  ]
}
