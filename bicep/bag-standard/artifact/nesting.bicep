targetScope = 'managementGroup'

param policysetValues object 
param s01enforcedTags object


// Module for S01 - Inherit Tags from RG
module InheritTagsPolicy '../bag-standard-policydefinitions/s01-inhertitTag.bicep' = [for (tag, i) in items(s01enforcedTags): {
  name: 'InheritTagsPolicyDeployment${i+1}'
  params: {
    policyVersion: policysetValues.policyVersion
    tag: tag.value
  }
}]

// Collect outputs from all module instances into a variable without the extra key
output inheritedTagPolicies array = [for (tag, i) in items(s01enforcedTags): {
  policyDefinitionId: InheritTagsPolicy[i].outputs.policyParameterObject.policyDefinitionId
  policyDefinitionReferenceId: InheritTagsPolicy[i].outputs.policyParameterObject.policyDefinitionReferenceId
  //parameters: InheritTagsPolicy[i].outputs.policyParameterObject.parameters
  groupNames: InheritTagsPolicy[i].outputs.policyParameterObject.groupNames
}]


output inheritedTagParamsForPolicySet array = [for (tag, i) in items(s01enforcedTags): {
  tag: InheritTagsPolicy[i].outputs.paramterForPolicySet.tag
    type: 'String'
    metadata: {
      displayName: 'Tag ${tag}'
      description: 'The tag name for ${tag}'
    }
}]
