targetScope = 'managementGroup'

param policysetValues object


param policyDefinitionsArray array
param usedParamsInPolicySet object

param appliedComplianceMessages array
param usedParamsInPolicyAssignment object

var policySetName = 'BAG-Base-Layer'

// Azure policy set definition
resource policySetDefinition 'Microsoft.Authorization/policySetDefinitions@2023-04-01' = {
  name: '${policySetName}-${policysetValues.policyVersion}'
  properties: {
    displayName: '${policysetValues.policySetDisplayName}-${policysetValues.policyVersion}'
    description: policysetValues.policySetDescription
    policyType: 'Custom'
    metadata: {
      category: 'General'
      version: policysetValues.policyVersion
    }
    parameters: usedParamsInPolicySet
    
    policyDefinitions: policyDefinitionsArray
    policyDefinitionGroups: [
      {
        name: 'S01-Bag-General'
        category: 'General'
      }
      {
        name: 'S02-Bag-Security'
        category: 'Security'
      }
    ]
  }
}


resource policySetAssignment 'Microsoft.Authorization/policyAssignments@2023-04-01' = {
  name: 'BAG-policies-${policysetValues.policyVersion}'
  location: 'switzerlandnorth'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    displayName: '${policysetValues.policyAssignmentDisplayName}-${policysetValues.policyVersion}'
    policyDefinitionId: policySetDefinition.id
    description: ''
    parameters: usedParamsInPolicyAssignment
    nonComplianceMessages: appliedComplianceMessages
    
  }
} 

resource contributorRoleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  name: 'b24988ac-6180-42a0-ab88-20f7382dd24c' // Contributor role ID
}

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(policySetAssignment.id, contributorRoleDefinition.id)
  properties: {
    roleDefinitionId: contributorRoleDefinition.id
    principalId: policySetAssignment.identity.principalId
    principalType: 'ServicePrincipal'
  }
}
