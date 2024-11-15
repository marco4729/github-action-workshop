targetScope = 'managementGroup'

param policyVersion string

param s01allowedLocations array

var policyDefinitionName = 'BAG-locations'
var policyDefinitionDescrpion = 'BAG-General Allowed Locations'

// Azure policy definition
resource policyDef 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: '${policyDefinitionName}-${policyVersion}'
  properties: {
    version: policyVersion
    description: 'This policy enables you to restrict the locations your organization can specify when deploying resources. Use to enforce your geo-compliance requirements. Excludes resource groups, Microsoft.AzureActiveDirectory/b2cDirectories, and resources that use the global region.'
    displayName: '${policyDefinitionDescrpion}-${policyVersion}'
    metadata: {
      version: policyVersion
      category: 'General'
    }
    mode: 'Indexed'
    parameters: {
      s01allowedLocations: {
        type: 'Array'
        metadata: {
          description: 'The list of locations that can be specified when deploying resources.'
          strongType: 'location'
          displayName: 'Allowed locations'
        }
        defaultValue: s01allowedLocations
      }
    }
    policyRule: {
      if: {
        allOf: [
          {
            field: 'location'
            notIn: '[parameters(\'s01allowedLocations\')]'
          }
          {
            field: 'location'
            notEquals: 'global'
          }
          {
            field: 'type'
            notEquals: 'Microsoft.AzureActiveDirectory/b2cDirectories'
          }
        ]
      }
      then: {
        effect: 'deny'
      }
    }
  }
}

////////////////////////////////
// Output Area
////////////////////////////////

output policyParameterObject object = {
  policyDefinitionId: policyDef.id
  policyDefinitionReferenceId: 'bags01allowedlocations'
  parameters: {
    s01allowedLocations: {
      value: '[parameters(\'s01allowedLocations\')]'
    }
  }
  groupNames: [
    'S01-Bag-General'
  ]
}
