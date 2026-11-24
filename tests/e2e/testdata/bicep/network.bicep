targetScope = 'resourceGroup'

@minLength(1)
@maxLength(40)
param namePrefix string

param location string = resourceGroup().location
param networkPrefix string = '10.72.0.0/16'
param subnetPrefix string = '10.72.1.0/24'

resource vnet 'Microsoft.Network/virtualNetworks@2025-07-01' = {
  name: '${namePrefix}-vnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        networkPrefix
      ]
    }
  }
}

resource outboundIP 'Microsoft.Network/publicIPAddresses@2025-09-01' = {
  name: '${namePrefix}-outbound'
  location: location
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
  }
}

resource nat 'Microsoft.Network/natGateways@2025-07-01' = {
  name: '${namePrefix}-nat'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    idleTimeoutInMinutes: 4
    publicIpAddresses: [
      {
        id: outboundIP.id
      }
    ]
  }
}

resource subnet 'Microsoft.Network/virtualNetworks/subnets@2024-07-01' = {
  parent: vnet
  name: 'workloads'
  properties: {
    addressPrefix: subnetPrefix
    defaultOutboundAccess: false
    natGateway: {
      id: nat.id
    }
  }
}

output subnetId string = subnet.id
output outboundIpId string = outboundIP.id
