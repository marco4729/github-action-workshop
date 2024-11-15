targetScope = 'managementGroup'

param policyVersion string

param tag string

var policyDefinitionName = 'BAG-inheritTag-${tag}'
var policyDefinitionDescrpion = 'BAG-General Inherit Tag ${tag} from Resourcegroups'

// Azure policy definition
resource policyDef 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: '${policyDefinitionName}-${policyVersion}'
  properties: {
    description: 'Adds the tag ${tag} with its value from the parent resource group when any resource missing that tag is created or updated. Existing resources can be remediated by triggering a remediation task. If a tag exists with a different value it will not be changed.'
    displayName: '${policyDefinitionDescrpion}-${policyVersion}'
    metadata: {
      version: policyVersion
      category: 'Tags'
    }
    mode: 'Indexed'
    parameters: {
      tag: {
        type: 'String'
        metadata: {
          displayName: 'Tag ${tag}'
          description: 'The tag name for ${tag}'
        }
        defaultValue: tag
      }
    }
    policyRule: {
      if: {
        anyOf: [
          {
            allOf: [
              {
                field: '[concat(\'tags[\', parameters(\'tag\'), \']\')]'
                exists: 'false'
              }
              {
                value: '[resourceGroup().tags[parameters(\'tag\')]]'
                notEquals: ''
              }
            ]
          }
        ]
      }
      then: {
        effect: 'modify'
        details: {
          roleDefinitionIds: [
            '/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c'
          ]
          operations: [
            {
              operation: 'add'
              field: '[concat(\'tags[\', parameters(\'tag\'), \']\')]'
              value: '[resourceGroup().tags[parameters(\'tag\')]]'
            }
          ]
        }
      }
    }
    policyType: 'Custom'
  }
}

////////////////////////////////
// Output Area
////////////////////////////////

output policyParameterObject object = {
  policyDefinitionId: policyDef.id
  policyDefinitionReferenceId: 'bags01inhertigtag${tag}'
  groupNames: [
    'S01-Bag-General'
  ]
}


output paramterForPolicySet object = {
  tag: {
    type: 'String'
    metadata: {
      displayName: 'Tag ${tag}'
      description: 'The tag name for ${tag}'
    }
  }
}
