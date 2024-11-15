////////////////////////////////////////////////////////
//
// Type:   Main
// Author:   Marco Florez
// CreationDate:   03.07.2024
// Name:   Azure Policy Deployment
// Description:   Deployment of standard Azure Policies as policySet
// Version:   1.0.0
//
////////////////////////////////////////////////////////

//////////////////////////////////
// Deployment scope
//////////////////////////////////

targetScope = 'managementGroup'


//////////////////////////////////
// MARK:  Parameter Area
//////////////////////////////////

param deployPolicyGroup object = {
  s01policies: true // will deploy the standard policies for S01
  s02policies: true // will deploy the standard policies for S02
}

param policysetValues object

@allowed([
  'Audit'
  'Deny'
])
param s01effect string = 'Deny'

@description('List of allowed locations')
param s01allowedLocations array

@description('Define 5 tags that are enforced at RG and inherited by resources')
param s01enforcedTags object = { 
  tag1: 'CreationDate'
  tag2: 'Creator'
  tag3: 'Description'
  tag4: 'Environment'
  // tag5: 'CostCenter'
}

@allowed([
  'Audit'
  'Disabled'
  'Deny'
])
param s02shouldTrustedLaunch string = 'Deny'

@allowed([
  'DeployIfNotExists'
  'Disabled'
])
param s02setvtpmeffect string = 'DeployIfNotExists'

@allowed([
  'DeployIfNotExists'
  'Disabled'
])
param s02setsecurebooteffect string = 'DeployIfNotExists' 


//////////////////////////////////
// MARK: Variable Area
//////////////////////////////////
// Logic to combine outputs and values from policyDefinitions depending deployment of S01 or S01+S02 Policies

var s01nestingPoliciesOutput = nestingPolicies.outputs.inheritedTagPolicies
var s01combinedOutput = concat(s01nestingPoliciesOutput, s01policiesOutput)
var s01policiesOutput = [
  EnforcedTagsPolicy.outputs.policyParameterObject
  AllowedLocationsPolicy.outputs.policyParameterObject
]

var s02policies = [
  shouldTrustedLaunch.outputs.policyParameterObject
  configurevTpm.outputs.policyParameterObject
  configurevSecureBootWin.outputs.policyParameterObject
  configurevSecureBootLinux.outputs.policyParameterObject
]
// combining the policydefinitions for the policyset depending on condition
var appliedPolicies = deployPolicyGroup.s01policies && deployPolicyGroup.s02policies ? concat (s01combinedOutput, s02policies) : s01combinedOutput

var s01paramsPolicySet = {
  tag1: {
    type: 'String'
    metadata: {
      displayName: 'Tag ${s01enforcedTags.tag1}'
      description: 'The tag name for ${s01enforcedTags.tag1}'
    }
    defaultValue: s01enforcedTags.tag1
  }
  tag2: {
    type: 'String'
    metadata: {
      displayName: 'Tag ${s01enforcedTags.tag2}'
      description: 'The tag name for ${s01enforcedTags.tag2}'
    }
    defaultValue: s01enforcedTags.tag2
  }
  tag3: {
    type: 'String'
    metadata: {
      displayName: 'Tag ${s01enforcedTags.tag3}'
      description: 'The tag name for ${s01enforcedTags.tag3}'
    }
    defaultValue: s01enforcedTags.tag3
  }
  tag4: {
    type: 'String'
    metadata: {
      displayName: 'Tag ${s01enforcedTags.tag4}'
      description: 'The tag name for ${s01enforcedTags.tag4}'
    }
    defaultValue: s01enforcedTags.tag4
  }
  // add parameter for tag5 whih is used in policyset definition
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
  s01allowedLocations: {
    type: 'Array'
    metadata: {
      displayName: 'Allowed Locations'
      description: 'The list of locations that can be specified when deploying resources.'
      strongType: 'location'
    }
    defaultValue: s01allowedLocations
  }
}

var s02paramsPolicySet = {
  s02shouldTrustedLaunch: {
    type: 'String'
    metadata: {
      description: 'Enable or disable the execution of the policy'
      displayName: 'Enforce Trusted Launch / ConfidentialVM with vTpm / Secureboot Effect'
    }
    allowedValues: [
      'Audit'
      'Disabled'
      'Deny'
    ]
    defaultValue: s02shouldTrustedLaunch
  }
  s02setvtpmeffect: {
    type: 'String'
    metadata: {
      description: 'Enable or disable the execution of the policy'
      displayName: 'Set vTPM on supported VMs Effect'
    }
    allowedValues: [
      'DeployIfNotExists'
      'Disabled'
    ]
    defaultValue: s02setvtpmeffect
  }
  s02setsecurebooteffect: {
    type: 'String'
    metadata: {
      description: 'Enable or disable the execution of the policy'
      displayName: 'Set secureBoot on supported VMs Effect'
    }
    allowedValues: [
      'DeployIfNotExists'
      'Disabled'
    ]
    defaultValue: s02setsecurebooteffect
  }
}
// combining the parameters for the policyset depending on condition
var usedParamsInPolicySet = deployPolicyGroup.s01policies && deployPolicyGroup.s02policies ? union(s01paramsPolicySet, s02paramsPolicySet) : s01paramsPolicySet

var s01paramsAssignment = {
  tag1: {
    value: s01enforcedTags.tag1
  }
  tag2: {
    value: s01enforcedTags.tag2
  }
  tag3: {
    value: s01enforcedTags.tag3
  }
  tag4: {
    value: s01enforcedTags.tag4
  }
  // add parameter for tag5 which is used in assignment
  s01effect: {
    value: s01effect
  }
  s01allowedLocations: {
    value: s01allowedLocations
  }
}

var s02paramsAssignment = {
  s02shouldTrustedLaunch: {
    value: s02shouldTrustedLaunch
  }
  s02setvtpmeffect: {
    value: s02setvtpmeffect
  }
  s02setsecurebooteffect: {
    value: s02setsecurebooteffect
  }
}

// combining the parameters for the policyAssignment depending on condition
var usedParamsInPolicyAssignment = deployPolicyGroup.s01policies && deployPolicyGroup.s02policies ? union(s01paramsAssignment, s02paramsAssignment) : s01paramsAssignment

var allowedLocationsString = join(s01allowedLocations, ', ')
var s01noncomplianceMessage = [
  {
    message: 'RG does not have the required tags. Please add the following tags: CreationDate, Creator, Description, Environment'
    policyDefinitionReferenceId: EnforcedTagsPolicy.outputs.policyParameterObject.policyDefinitionReferenceId
  }
  {
    message: 'The resource location is not allowed. Allowed locations are: ${allowedLocationsString}'
    policyDefinitionReferenceId: AllowedLocationsPolicy.outputs.policyParameterObject.policyDefinitionReferenceId
  }
]

var s02noncomplianceMessage = [
  {
    message: 'The VM does not have TrustedLaunch or ConfidentialVM enabled andOr is missing vTpm + Secureboot Setting'
    policyDefinitionReferenceId: shouldTrustedLaunch.outputs.policyParameterObject.policyDefinitionReferenceId
  }
  {
    message: 'Can not enable vTPM on that VM. Please contact baggenstos support.'
    policyDefinitionReferenceId: configurevTpm.outputs.policyParameterObject.policyDefinitionReferenceId
  }
  {
    message: 'Can not enable secureBoot on that Windows VM. Please contact baggenstos support.'
    policyDefinitionReferenceId: configurevSecureBootWin.outputs.policyParameterObject.policyDefinitionReferenceId
  }
  {
    message: 'Can not enable secureBoot on that Linux VM. Please contact baggenstos support.'
    policyDefinitionReferenceId: configurevSecureBootLinux.outputs.policyParameterObject.policyDefinitionReferenceId
  }
]
var appliedComplianceMessages = deployPolicyGroup.s01policies && deployPolicyGroup.s02policies ? concat (s01noncomplianceMessage, s02noncomplianceMessage) : s01noncomplianceMessage


// --- Deployments of Custom Policies ---
// MARK: Modules - policy definitions
// Module for S01 - Enforce Tags on RG Policy
module EnforcedTagsPolicy 'bag-standard-policydefinitions/s01-enforceTagsOnRg.bicep' = if (deployPolicyGroup.s01policies) {
  name: 'EnforcedTagsPolicyDeployment'
  params: {
    policyVersion: policysetValues.policyVersion
    tag1: s01enforcedTags.tag1
    tag2: s01enforcedTags.tag2
    tag3: s01enforcedTags.tag3
    tag4: s01enforcedTags.tag4
    // add parameter for tag5 if used
    s01effect: s01effect
  }
}

// Intermediary Module for S01 - Inherit Tag from RG, needed for using the output as an array in the policySet
module nestingPolicies 'artifact/nesting.bicep' = if (deployPolicyGroup.s01policies) {
  name: 'nestingPolicies'
  params: {
    policysetValues: policysetValues
    s01enforcedTags: s01enforcedTags
  }
}

// Module for S01 -  Allowed Locations Policy
module AllowedLocationsPolicy 'bag-standard-policydefinitions/s01-allowedLocations.bicep' = if (deployPolicyGroup.s01policies) {
  name: 'AllowedLocationsPolicyDeployment'
  params: {
    policyVersion: policysetValues.policyVersion
    s01allowedLocations: s01allowedLocations
  }
}

// Module for S02 - should SecureBoot on supported Linux VMs
module shouldTrustedLaunch 'bag-standard-policydefinitions/s02-shouldTrustedLaunch.bicep' = if (deployPolicyGroup.s02policies) {
  name: 'ShouldTrustedLaunchOnVmsDeployment'
  params: {
    policyVersion: policysetValues.policyVersion
    s02shouldTrustedLaunch: s02shouldTrustedLaunch
  }
}

// Module for S02 - set vTPM on supported VMs
module configurevTpm 'bag-standard-policydefinitions/s02-configurevTpm.bicep' = if (deployPolicyGroup.s02policies) {
  name: 'ShouldSetVtpmOnSupportedVmsDeployment'
  params: {
    policyVersion: policysetValues.policyVersion
    s02setvtpmeffect: s02setvtpmeffect
  }
}

// Module for S02 - set secureBoot on supported Windows VMs
module configurevSecureBootWin 'bag-standard-policydefinitions/s02-configurevSecureBootWin.bicep' = if (deployPolicyGroup.s02policies) {
  name: 'ShouldSetSecBootOnWinVmsDeployment'
  params: {
    policyVersion: policysetValues.policyVersion
    s02setsecurebooteffect: s02setsecurebooteffect
  }
}

// Module for S02 - set secureBoot on supported Linux VMs
module configurevSecureBootLinux 'bag-standard-policydefinitions/s02-configurevSecureBootLinux.bicep' = if (deployPolicyGroup.s02policies) {
  name: 'ShouldSetSecBootOnLinuxVmsDeployment'
  params: {
    policyVersion: policysetValues.policyVersion
    s02setsecurebooteffect: s02setsecurebooteffect
  }
}

// --- Deployment of PolicySet - Initiative ---
// MARK: Module - policySet
////////////////////////////////
// Policy Set
////////////////////////////////

module PolicySet 'bag-standard-policyinitiative/bag-standard-policyset.bicep' = {
  name: 'bag-standard-policyset'
  params: {
    appliedComplianceMessages: appliedComplianceMessages
    policysetValues: policysetValues
    usedParamsInPolicySet: usedParamsInPolicySet
    usedParamsInPolicyAssignment: usedParamsInPolicyAssignment
    policyDefinitionsArray: appliedPolicies
  }
}

