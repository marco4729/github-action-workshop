param location string = 'switzerlandnorth'
param resourceGroupName string = 'demo-rg'
param storageAccountName string = 'mystorage5555553b'
param vnetName string = 'demo-vnet'
param vnetAddressPrefix string = '10.0.0.0/16'
param subnetName string = 'default'
param subnetPrefix string = '10.0.1.0/24'

targetScope = 'subscription'

resource resourceGroup 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
}
module vnetModule 'modules/vnet.bicep' = {
  name: 'deployVNet'
  scope: resourceGroup
  params: {
    vnetName: vnetName
    location: location
    vnetAddressPrefix: vnetAddressPrefix
    subnetName: subnetName
    subnetPrefix: subnetPrefix
  }
}

module storageAccountModule 'modules/storageacc.bicep' = {
  name: 'deployStorageAccount'
  scope: resourceGroup
  params: {
    storageAccountName: storageAccountName
    location: location
  }
}
