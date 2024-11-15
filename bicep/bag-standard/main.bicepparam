/*
# For Lifecycle Purpose of the policies we use a deployment stack, use the following script to deploy the policies

# Define variables
$managementGroupId = "mg1"
$location = "switzerlandnorth"
$stackName = "mgpolicystd1"
$description = "desc. This is a deployment stack of bag standard policies 1.0.0"
$tags = @{"CreatedAt"="01.09.24"; "Creator"="yourname"; "Description"="a description"; "Environment"="production"}

az stack mg create `
  --management-group-id $managementGroupId `
  --name $stackName `
  --location $location `
  --template-file 'main.bicep' `
  --parameters 'main.bicepparam' `
  --action-on-unmanage 'deleteAll' `
  --deny-settings-mode 'none' `
  --description $description `
  --tags $tags

*/


using './main.bicep'

param deployPolicyGroup = {
  s01policies: true
  s02policies: true
}

param policysetValues = {
  policySetDisplayName: 'BAG-Base-Layer-PolicySet'
  policySetDescription: 'The policySet contains the standard policies used at Baggenstos'
  policyVersion: '1.0.0'
  policyAssignmentDisplayName: 'BAG-Base-Layer'
}

@description('List of allowed locations')
param s01allowedLocations = [
  'switzerlandnorth'
  'switzerlandwest'
]

@description('Define 4 tags that are enforced at RG and inherited by resources')
param s01enforcedTags = {
  tag1: 'CreationDate'
  tag2: 'Creator'
  tag3: 'Description'
  tag4: 'Environment'
}

@allowed([
  'Audit'
  'Deny'
])
@description('Define the effect for Tag & location enforcement')
param s01effect = 'Deny'

@allowed([
  'Audit'
  'Disabled'
  'Deny'
])
param s02shouldTrustedLaunch = 'Deny'
