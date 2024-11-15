targetScope = 'managementGroup'

param policyVersion string

param s01effect string

param tag1 string
param tag2 string
param tag3 string
param tag4 string
// param tag5 string

var policyDefinitionName = 'BAG-enforceTagRg'
var policyDefinitionDescrpion = 'BAG-General Enforce Tags on Resourcegroups'

// Azure policy definition
resource policyDef 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: '${policyDefinitionName}-${policyVersion}'
  properties: {
    version: policyVersion
    description: 'Enforces required tags and their values on resource groups.'
    displayName: '${policyDefinitionDescrpion}-${policyVersion}'
    metadata: {
      version: policyVersion
      category: 'Tags'
    }
    mode: 'All'
    parameters: {
      tag1: {
        type: 'String'
        metadata: {
          displayName: 'Tag ${tag1}'
          description: 'The tag name for ${tag1}'
        }
        defaultValue: tag1
      }
      tag2: {
        type: 'String'
        metadata: {
          displayName: 'Tag ${tag2}'
          description: 'The tag name for ${tag2}'
        }
        defaultValue: tag2
      }
      tag3: {
        type: 'String'
        metadata: {
          displayName: 'Tag ${tag3}'
          description: 'The tag name for ${tag3}'
        }
        defaultValue: tag3
      }
      tag4: {
        type: 'String'
        metadata: {
          displayName: 'Tag ${tag4}'
          description: 'The tag name for ${tag4}'
        }
        defaultValue: tag4
      }
      // add more parameters for new tags here
      s01effect: {
        type: 'String'
        metadata: {
          displayName: 'Enforce Tags on RGs Effect'
          description: 'Deny, Audit or Disabled the execution of the Policy'
        }
        allowedValues: [
          'Deny'
          'Audit'
          'Disabled'
        ]
        defaultValue: s01effect
      }
    }
    policyRule: {
      if: {
        allOf: [
          {
            field: 'type'
            equals: 'Microsoft.Resources/subscriptions/resourceGroups'
          }
          {
            field: '[concat(\'tags[\', parameters(\'tag1\'), \']\')]'
            exists: false
          }
          {
            field: '[concat(\'tags[\', parameters(\'tag1\'), \']\')]'
            notEquals: ''
          }
          {
            field: '[concat(\'tags[\', parameters(\'tag2\'), \']\')]'
            exists: false
          }
          {
            field: '[concat(\'tags[\', parameters(\'tag2\'), \']\')]'
            notEquals: ''
          }
          {
            field: '[concat(\'tags[\', parameters(\'tag3\'), \']\')]'
            exists: false
          }
          {
            field: '[concat(\'tags[\', parameters(\'tag3\'), \']\')]'
            notEquals: ''
          }
          {
            field: '[concat(\'tags[\', parameters(\'tag4\'), \']\')]'
            exists: false
          }
          {
            field: '[concat(\'tags[\', parameters(\'tag4\'), \']\')]'
            notEquals: ''
          }
          // add policy rules for new tags here
        ]
      }
      then: {
        effect: '[parameters(\'s01effect\')]'
      }
    }
    policyType: 'Custom'
  }
}

////////////////////////////////
// Output Area
////////////////////////////////

// 
output policyParameterObject object = {
  policyDefinitionId: policyDef.id
  policyDefinitionReferenceId: 'bags01enforcetagsonrg'
  parameters: {
    tag1: {
      value: '[parameters(\'tag1\')]'
    }
    tag2: {
      value: '[parameters(\'tag2\')]'
    }
    tag3: {
      value: '[parameters(\'tag3\')]'
    }
    tag4: {
      value: '[parameters(\'tag4\')]'
    }
    // add the used parameter to the output which will be used in the initiative

    s01effect: {
      value: '[parameters(\'s01effect\')]'
    }
  }
  groupNames: [
    'S01-Bag-General'
  ]
}
