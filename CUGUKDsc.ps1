
function Get-DscSplattedResource
{
<#
    .NOTES
        Adapted from https://gaelcolas.com/2017/11/05/pseudo-splatting-dsc-resources/
#>
    [CmdletBinding()]
    [Alias('x')]
    param
    (
        [System.String]
        $ResourceName,

        [System.String]
        $ExecutionName,

        [System.Collections.Hashtable]
        $Properties
    )
    begin
    {
        if ($PSBoundParameters.ContainsKey('Debug'))
        {
            $DebugPreference = 'Continue'
        }
        else
        {
            $DebugPreference = 'SilentlyContinue'
        }
    }
    process
    {
        $ExecutionName = $ExecutionName -ireplace '<|!|#|>' ,'' -ireplace '\s|\.', '_'

        $replacementTokenMap = @{
            '<!#DomainName#!>'        = $ConfigurationData.NonNodeData.ActiveDirectory.DomainName
            '<!#DomainDN#!>'          = $ConfigurationData.NonNodeData.ActiveDirectory.DomainDN
            '<!#FQDN#!>'              = $Node._FQDN
            '<!#NetBIOS#!>'           = $Node._NetBIOS
            '<!#CommonName#!>'        = 'cn={0}' -f $Node._NetBIOS.ToLower()
            '<!#CN#!>'                = 'cn={0}' -f $Node._NetBIOS.ToLower()
            '<!#DN#!>'                = 'cn={0},{1}' -f $Node._NetBIOS.ToLower(), $ConfigurationData.NonNodeData.ActiveDirectory.DomainDN.ToLower()
            '<!#DistinguishedName#!>' = 'cn={0},{1}' -f $Node._NetBIOS.ToLower(), $ConfigurationData.NonNodeData.ActiveDirectory.DomainDN.ToLower()
            '<!#CvadVersion#!>'       = $cvadFullVersion # 1912CU1
            '<!#CvadFullVersion#!>'   = $cvadFullVersion # 1912CU1
            '<!#CvadShortVersion#!>'  = $cvadShortVersion # 1912U1
            '<!#CvadMajorVersion#!>'  = $cvadMajorVersion # 1912
            '<!#CvadUpdateVersion#!>' = $cvadUpdateVersion # 1
        }

        $tokenisedProperties = @{}
        $stringBuilder = [System.Text.StringBuilder]::New()
        $null = $stringBuilder.AppendLine("Param([hashtable]`$Parameters)")
        $null = $stringBuilder.AppendLine(" $ResourceName $ExecutionName { ")
        foreach ($propertyName in $Properties.Keys)
        {
            $propertyValue = $Properties[$propertyName]
            if ($Properties[$propertyName] -is [System.String])
            {
                foreach ($replacementToken in $replacementTokenMap.GetEnumerator())
                {
                    $propertyValue = $propertyValue -ireplace $replacementToken.Key, $replacementToken.Value
                }
            }
            $tokenisedProperties[$propertyName] = $propertyValue
            $null = $stringBuilder.AppendLine("$propertyName = `$(`$Parameters['$propertyName'])")
        }
        $null = $stringBuilder.AppendLine("}")
        Write-Debug ("Generated Resource Block = {0}" -f $stringBuilder.ToString())
        [System.Management.Automation.ScriptBlock]::Create($stringBuilder.ToString()).Invoke($tokenisedProperties)
    }
}

[DSCLocalConfigurationManager()]
configuration CUGUKLcm
{
    param ( )

    node $AllNodes.NodeName
    {
        Settings
        {
            RebootNodeIfNeeded   = if ($Node.ContainsKey('RebootNodeIfNeeded')) { $Node.RebootNodeIfNeeded } else { $true }
            AllowModuleOverwrite = if ($Node.ContainsKey('AllowModuleOverwrite')) { $Node.AllowModuleOverwrite } else { $true }
            DebugMode            = if ($Node.ContainsKey('DebugMode')) { $Node.DebugMode } else { 'ForceModuleImport' }
            ConfigurationId      = if ($Node.ContainsKey('Guid')) { $Node.Guid } else { (New-Guid).Guid }
            ConfigurationMode    = if ($Node.ContainsKey('ConfigurationMode')) { $Node.ConfigurationMode } else { 'ApplyOnly' }
        }

        ResourceRepositoryShare SmbResourceShare
        {
            SourcePath = $ConfigurationData.NonNodeData.DscResourcePath
        }
    }
}

configuration CUGUKDsc
{
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration, NetworkingDsc, CertificateDsc, xWebAdministration, XenDesktop7

    $cvadMajorVersion = (($ConfigurationData.NonNodeData.Citrix.XenDesktop.Version -split 'C?U')[0] -as [System.Int32]).ToString()
    $cvadUpdateVersion = (($ConfigurationData.NonNodeData.Citrix.XenDesktop.Version -split 'C?U')[1] -as [System.Int32]).ToString()
    $cvadFullVersion = '{0}CU{1}' -f $cvadMajorVersion, $cvadUpdateVersion
    $cvadShortVersion = '{0}U{1}' -f $cvadMajorVersion, $cvadUpdateVersion

    ## Ensure we have a domain DN
    if (-not $ConfigurationData.NonNodeData.ActiveDirectory.ContainsKey('DomainDN'))
    {
        $ConfigurationData.NonNodeData.ActiveDirectory['DomainDN'] = 'dc={0}' -f ($ConfigurationData.NonNodeData.ActiveDirectory.DomainName -split '\.' -join ',dc=')
    }

    ## Ensure every node has a _Fqdn and _NetBIOS property
    foreach ($dscNode in $AllNodes)
    {
        if ($dscNode.NodeName.Contains('.'))
        {
            $dscNode['_Fqdn'] = $dscNode.NodeName.ToLower()
            $dscNode['_NetBIOS'] = ($dscNode.NodeName.Split('.')[0]).ToUpper()
        }
        else
        {
            $dscNode['_Fqdn'] = ('{0}.{1}' -f $dscNode.NodeName, $ConfigurationData.NonNodeData.ActiveDirectory.DomainName).ToLower()
            $dscNode['_NetBIOS'] = $dscNode.NodeName.ToUpper()
        }
    }

    $primaryDeliveryController = $AllNodes | Where-Object { $_.Role -contains 'Controller' } | Select-Object -First 1
    $secondaryDeliveryControllers = $AllNodes | Where-Object { $_.Role -contains 'Controller' } | Select-Object -Skip 1
    $allDeliveryControllers = $AllNodes | Where-Object { $_.Role -contains 'Controller' }

    $citrixData = $ConfigurationData.NonNodeData.Citrix
    if ($citrixData.ContainsKey('NetScaler'))
    {
        $netScalerData = $ConfigurationData.NonNodeData.Citrix.NetScaler
    }
    $adData = $ConfigurationData.NonNodeData.ActiveDirectory

    node $AllNodes.NodeName
    {
        if ($Node.Role -contains 'FAS')
        {
            $xd7FeatureParams = @{
                Role = 'FAS'
                SourcePath = Join-Path -Path $citrixData.XenDesktop.MediaRootPath -ChildPath $citrixData.XenDesktop.Version
            }
            x XD7Feature 'XD7FAS' $xd7FeatureParams
        }

        $nonFasFeatures = $Node.Role | Where-Object { $_ -ne 'FAS' }
        if ($null -ne $nonFasFeatures)
        {
            $xd7FeaturesParams = @{
                IsSingleInstance = 'Yes'
                Role = $nonFasFeatures
                SourcePath = Join-Path -Path $citrixData.XenDesktop.MediaRootPath -ChildPath $citrixData.XenDesktop.Version
                IgnoreHardwareCheckFailure = $true
            }
            x XD7Features 'XD7Features' $xd7FeaturesParams
        }
    }

    node $AllNodes.Where({$_.Role -contains 'Controller'}).NodeName {

        if ($citrixData.XenDesktop.ContainsKey('Certificate'))
        {
            if (-not $citrixData.XenDesktop.Certificate.ContainsKey('CARootName'))
            {
                $citrixData.XenDesktop.Certificate['CARootName'] = $adData.CARootName
            }
            if (-not $citrixData.XenDesktop.Certificate.ContainsKey('CAServerFQDN'))
            {
                $citrixData.XenDesktop.Certificate['CAServerFQDN'] = $adData.CAServerFQDN
            }

            $citrixData.XenDesktop.Certificate['Credential'] = $Credential
            x CertReq 'ServerCertificate' $citrixData.XenDesktop.Certificate
        }
    }
    
    node $primaryDeliveryController.NodeName {

        $siteDatabaseParams = @{
            SiteName             = $citrixData.XenDesktop.Site.SiteName
            DataStore            = 'Site'
            DatabaseServer       = $citrixData.XenDesktop.Site.DatabaseServer
            DatabaseName         = $citrixData.XenDesktop.Site.SiteDbName
            PsDscRunAsCredential = $Credential
            DependsOn            = '[XD7Features]XD7Features'
        }
        x XD7Database 'XD7SiteDatabase' $siteDatabaseParams

        $loggingDatabaseParams = @{
            SiteName             = $citrixData.XenDesktop.Site.SiteName
            DataStore            = 'Logging'
            DatabaseServer       = $citrixData.XenDesktop.Site.DatabaseServer
            DatabaseName         = $citrixData.XenDesktop.Site.LoggingDbName
            PsDscRunAsCredential = $Credential
            DependsOn            = '[XD7Features]XD7Features'
        }
        x XD7Database 'XD7LoggingDatabase' $loggingDatabaseParams

        $monitorDatabaseParams = @{
            SiteName             = $citrixData.XenDesktop.Site.SiteName
            DataStore            = 'Monitor'
            DatabaseServer       = $citrixData.XenDesktop.Site.DatabaseServer
            DatabaseName         = $citrixData.XenDesktop.Site.MonitorDbName
            PsDscRunAsCredential = $Credential
            DependsOn            = '[XD7Features]XD7Features'
        }
        x XD7Database 'XD7MonitorDatabase' $monitorDatabaseParams

        $siteParams = @{
            SiteName             = $citrixData.XenDesktop.Site.SiteName
            DatabaseServer       = $citrixData.XenDesktop.Site.DatabaseServer
            SiteDatabaseName     = $citrixData.XenDesktop.Site.SiteDbName
            LoggingDatabaseName  = $citrixData.XenDesktop.Site.LoggingDbName
            MonitorDatabaseName  = $citrixData.XenDesktop.Site.MonitorDbName
            PsDscRunAsCredential = $Credential
            DependsOn            = '[XD7Database]XD7SiteDatabase','[XD7Database]XD7LoggingDatabase','[XD7Database]XD7MonitorDatabase'
        }
        x XD7Site 'XD7Site' $siteParams

        if ($citrixData.XenDesktop.Site.ContainsKey('Licensing'))
        {
            $citrixData.XenDesktop.Site.Licensing['PsDscRunAsCredential'] = $Credential
            $citrixData.XenDesktop.Site.Licensing['DependsOn'] = '[XD7Site]XD7Site'
            x XD7SiteLicense 'XD7SiteLicense' $citrixData.XenDesktop.Site.Licensing
        }

        if ($citrixData.XenDesktop.Site.ContainsKey('SiteConfig'))
        {
            $citrixData.XenDesktop.Site.SiteConfig['IsSingleInstance'] = 'Yes'
            $citrixData.XenDesktop.Site.SiteConfig['PsDscRunAsCredential'] = $Credential
            $citrixData.XenDesktop.Site.SiteConfig['DependsOn'] = '[XD7Site]XD7Site'
            x XD7SiteConfig 'XD7SiteConfig' $citrixData.XenDesktop.Site.SiteConfig
        }

        if ($citrixData.XenDesktop.Site.ContainsKey('Delegation'))
        {
            if ($citrixData.XenDesktop.Site.Delegation.ContainsKey('Administrators'))
            {
                foreach ($administrator in $citrixData.XenDesktop.Site.Delegation.Administrators)
                {
                    $xd7AdministratorParams = @{
                        Name                 = $administrator
                        PsDscRunAsCredential = $Credential
                        DependsOn            = '[XD7Site]XD7Site'
                    }
                    x XD7Administrator $administrator $xd7AdministratorParams
                }
            }

            if ($citrixData.XenDesktop.Site.Delegation.ContainsKey('Roles'))
            {
                foreach ($role in $citrixData.XenDesktop.Site.Delegation.Roles)
                {
                    $role['PsDscRunAsCredential'] = $Credential
                    $role['DependsOn'] =
                    x XD7Role $role.Name $role
                }
            }
        }
    }

    node $secondaryDeliveryControllers.NodeName {

        WaitForAll 'XD7Site'
        {
            ResourceName     = '[XD7Site]XD7Site'
            NodeName         = $primaryDeliveryController.NodeName
            RetryIntervalSec = 60
            RetryCount       = 60
            DependsOn        = '[XD7Features]XD7Features'
        }

        $controllerParams = @{
            SiteName               = $citrixData.XenDesktop.Site.SiteName
            ExistingControllerName = $primaryDeliveryController.NodeName
            PsDscRunAsCredential   = $Credential
            DependsOn              = '[WaitForAll]XD7Site'
        }
        x XD7Controller 'XD7Controller' $controllerParams
    }

    node $AllNodes.Where({$_.Role -contains 'Storefront'}).NodeName {

        if ($citrixData.Storefront.ContainsKey('Certificate'))
        {
            if (-not $citrixData.Storefront.Certificate.ContainsKey('CARootName'))
            {
                $citrixData.Storefront.Certificate['CARootName'] = $adData.CARootName
            }
            if (-not $citrixData.Storefront.Certificate.ContainsKey('CAServerFQDN'))
            {
                $citrixData.Storefront.Certificate['CAServerFQDN'] = $adData.CAServerFQDN
            }

            $citrixData.Storefront.Certificate['Credential'] = $Credential
            x CertReq 'ServerCertificate' $citrixData.Storefront.Certificate
        }

        foreach ($hostsFile in $citrixData.Storefront.Hosts)
        {
            $hostsFileName = $hostsFile.HostName.Replace(',' ,'_')
            x HostsFile $hostsFileName $hostsFile
        }

        $storefrontParams = @{
            SiteId      = 1
            HostBaseUrl = 'https://{0}' -f $citrixData.Storefront.BaseHostname
            DependsOn   = '[XD7Features]XD7Features'
        }
        x XD7Storefront 'XD7Storefront' $storefrontParams

        $commonName = 'cn={0}' -f $Node._NetBIOS.ToLower()
        xWebSite 'DefaultWebSite' {
            Name = 'Default Web Site';
            PhysicalPath = 'C:\inetpub\wwwroot';
            BindingInfo = @(
                MSFT_xWebBindingInformation  { Protocol = 'HTTPS'; Port = 443; CertificateSubject = $commonName; CertificateStoreName = 'My'; }
                MSFT_xWebBindingInformation  { Protocol = 'HTTP'; Port = 80; }
            )
            DependsOn = '[XD7Storefront]XD7Storefront'
        }

        foreach ($authenticationService in $citrixData.Storefront.AuthenticationServices)
        {
            $storeFrontAuthenticationServiceParams = @{
                FriendlyName = $authenticationService.FriendlyName
                VirtualPath  = $authenticationService.VirtualPath
                DependsOn    = '[XD7Storefront]XD7Storefront'
            }
            x XD7StoreFrontAuthenticationService $authenticationService.FriendlyName $storeFrontAuthenticationServiceParams

            $storeFrontAuthenticationServiceProtocolParams = @{
                VirtualPath            = $authenticationService.VirtualPath
                AuthenticationProtocol = $authenticationService.AuthenticationProtocol
                DependsOn              = '[XD7StoreFrontAuthenticationService]{0}' -f $authenticationService.FriendlyName
            }
            x XD7StoreFrontAuthenticationServiceProtocol $authenticationService.FriendlyName $storeFrontAuthenticationServiceProtocolParams
        }

        foreach ($store in $citrixData.Storefront.Stores)
        {
            $storeParams = $store.Clone()
            $storeParams.Remove('LaunchOptions')
            $storeParams.Remove('ExplicitCommonOptions')
            $storeParams.Remove('Farm')
            $storeParams.Remove('WebReceiver')
            $storeParams.Remove('AccessGatewayVirtualServer')
            x XD7StoreFrontStore $store.StoreName $storeParams

            if ($store.ContainsKey('ExplicitCommonOptions'))
            {
                $store.ExplicitCommonOptions['StoreName'] = $store.StoreName
                $store.ExplicitCommonOptions['DependsOn'] = '[XD7StoreFrontStore]{0}' -f $store.StoreName
                x XD7StoreFrontExplicitCommonOptions $store.StoreName $store.ExplicitCommonOptions
            }

            if ($store.ContainsKey('Farm'))
            {
                $farmParams = $store.Farm.Clone()
                $farmParams.Remove('Configuration')
                $farmParams['StoreName'] = $store.StoreName
                if (-not $store.Farm.ContainsKey('Servers'))
                {
                    $farmServers = $allDeliveryControllers._Fqdn
                    $farmParams['Servers'] = $farmServers
                }
                if (-not $farmParams.ContainsKey('FarmName'))
                {
                    $farmParams['FarmName'] = $citrixData.XenDesktop.Site.SiteName
                }
                if (-not $farmParams.ContainsKey('Port'))
                {
                    if ($farmParams.TransportType -eq 'HTTP')
                    {
                        $farmParams['Port'] = 80
                    }
                    else
                    {
                        $farmParams['Port'] = 443
                    }
                }
                if (-not $farmParams.ContainsKey('FarmType'))
                {
                    $farmParams['FarmType'] = 'XenDesktop'
                }
                $farmParams['DependsOn'] = '[XD7StoreFrontStore]{0}' -f $store.StoreName
                x XD7StoreFrontStoreFarm $store.StoreName $farmParams

                if ($store.Farm.ContainsKey('Configuration'))
                {
                    $store.Farm.Configuration['StoreName'] = $store.StoreName
                    $store.Farm.Configuration['DependsOn'] = '[XD7StoreFrontStoreFarm]{0}' -f $store.StoreName
                    x XD7StoreFrontFarmConfiguration $store.StoreName $store.Farm.Configuration
                }
            }

            if ($store.ContainsKey('WebReceiver'))
            {
                if ($store.WebReceiver.ContainsKey('Service'))
                {
                    $store.WebReceiver.Service['StoreName'] = $store.StoreName
                    $store.WebReceiver.Service['VirtualPath'] = '{0}Web' -f $store.StoreVirtualPath
                    $store.WebReceiver.Service['SiteId'] = 1
                    $store.WebReceiver.Service['DependsOn'] = '[XD7StoreFrontStore]{0}' -f $store.StoreName
                    x XD7StoreFrontWebReceiverService $store.StoreName $store.WebReceiver.Service

                    if ($store.WebReceiver.ContainsKey('Communication'))
                    {
                        $store.WebReceiver.Communication['StoreName'] = $store.StoreName
                        $store.WebReceiver.Communication['DependsOn'] = '[XD7StoreFrontWebReceiverService]{0}' -f $store.StoreName
                        x XD7StoreFrontWebReceiverCommunication $store.StoreName $store.WebReceiver.Communication
                    }

                    if ($store.WebReceiver.ContainsKey('PluginAssistant'))
                    {
                        $store.WebReceiver.PluginAssistant['StoreName'] = $store.StoreName
                        $store.WebReceiver.PluginAssistant['DependsOn'] = '[XD7StoreFrontWebReceiverService]{0}' -f $store.StoreName
                        x XD7StoreFrontWebReceiverPluginAssistant $store.StoreName $store.WebReceiver.PluginAssistant
                    }

                    if ($store.WebReceiver.ContainsKey('UserInterface'))
                    {
                        $store.WebReceiver.UserInterface['StoreName'] = $store.StoreName
                        $store.WebReceiver.UserInterface['DependsOn'] = '[XD7StoreFrontWebReceiverService]{0}' -f $store.StoreName
                        x XD7StoreFrontWebReceiverUserInterface $store.StoreName $store.WebReceiver.UserInterface
                    }

                    if ($store.WebReceiver.ContainsKey('SiteStyle'))
                    {
                        $store.WebReceiver.SiteStyle['StoreName'] = $store.StoreName
                        $store.WebReceiver.SiteStyle['DependsOn'] = '[XD7StoreFrontWebReceiverService]{0}' -f $store.StoreName
                        x XD7StoreFrontWebReceiverSiteStyle $store.StoreName $store.WebReceiver.SiteStyle
                    }
                }
            }
        }

        if ($netScalerData.ContainsKey('AccessGatewayVirtualServers'))
        {
            foreach ($vip in $netScalerData.AccessGatewayVirtualServers.GetEnumerator())
            {
                $virtualServer = $vip.Value
                $virtualServerStore = $citrixData.Storefront.Stores | Where-Object { $_.StoreName -eq $vip.Key }

                if ($virtualServerStore.ContainsKey('AccessGatewayVirtualServer'))
                {
                    $accessGatewayVirtualServer = $virtualServerStore.AccessGatewayVirtualServer
                    if (-not $accessGatewayVirtualServer.ContainsKey('Name'))
                    {
                        $gatewayHost = $accessGatewayVirtualServer.GatewayUrl.Split('.')[0]
                        $accessGatewayVirtualServer['Name'] = ('{0}_{1}_{2}' -f $netScalerData.Defaults.Prefixes.VServer, $gatewayHost, $cvadFullVersion).ToLower().Replace('.','_')
                    }

                    if ($accessGatewayVirtualServer.GatewayUrl -notmatch '^https?://')
                    {
                        $accessGatewayVirtualServer['GatewayUrl'] = 'https://{0}' -f $accessGatewayVirtualServer.GatewayUrl
                    }

                    if (-not $accessGatewayVirtualServer.ContainsKey('SecureTicketAuthorityUrls'))
                    {
                        $staProtocol = 'HTTPS'
                        $staPortSuffix = $null
                        if ($virtualServerStore.ContainsKey('Farm') -and $virtualServerStore.Farm.ContainsKey('TransportType'))
                        {
                            if ($virtualServerStore.Farm.TransportType -eq 'HTTPS')
                            {
                                if (($virtualServerStore.Farm.ContainsKey('Port')) -and ($virtualServerStore.Farm.Port -ne 443))
                                {
                                    $staPortSuffix = ':{0}' -f $virtualServerStore.Farm.Port
                                }
                            }
                            elseif ($virtualServerStore.Farm.TransportType -eq 'HTTP')
                            {
                                $staProtocol = 'HTTP'
                                if (($virtualServerStore.Farm.ContainsKey('Port')) -and ($virtualServerStore.Farm.Port -ne 80))
                                {
                                    $staPortSuffix = ':{0}' -f $virtualServerStore.Farm.Port
                                }
                            }
                        }

                        $secureTicketAuthorityUrls = @()
                        foreach ($deliveryController in $allDeliveryControllers)
                        {
                            $secureTicketAuthorityUrls += ('{0}://{1}{2}/scripts/ctxsta.dll' -f $staProtocol, $deliveryController._Fqdn, $staPortSuffix).ToLower()
                        }
                        $accessGatewayVirtualServer['SecureTicketAuthorityUrls'] = $secureTicketAuthorityUrls
                    }

                    if (-not $accessGatewayVirtualServer.ContainsKey('SubnetIPAddress'))
                    {
                        $accessGatewayVirtualServer['SubnetIPAddress'] = $virtualServer.IPAddress
                    }

                    x XD7StoreFrontRoamingGateway $vip.Key $accessGatewayVirtualServer

                    $XD7StoreFrontRegisterStoreGatewayParams = @{
                        StoreName = $vip.Key
                        GatewayName = $accessGatewayVirtualServer.Name
                        EnableRemoteAccess = $true
                    }
                    x XD7StoreFrontRegisterStoreGateway $vip.Key $XD7StoreFrontRegisterStoreGatewayParams
                }
            }
        } 
    }

    node $AllNodes.Where({$_.Role -contains 'Director'}).NodeName
    {
        xWebConfigKeyValue $Node.NodeName
        {
            ConfigSection = 'AppSettings'
            Key           = 'Service.AutoDiscoveryAddresses'
            Value         = [System.String]::Join(',', $allDeliveryControllers._Fqdn)
            IsAttribute   = $false
            WebsitePath   = 'IIS:\Sites\Default Web Site\Director'
            DependsOn     = '[XD7Features]XD7Features'
        }
    }

}
