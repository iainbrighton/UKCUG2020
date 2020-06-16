<#
    TOKEN                                DESCRIPTION
    =========================================================================================================
    <!#DomainName#!>                   = Active Directory fully-qualified domain name, e.g. lab.local
    <!#DomainDN#!>                     = Active Directory domain distinguished name, e,g, dc=lab,dc=local
    <!#FQDN#!>                         = Node's fully qualified domain name, e.g. srvddc01.lab.local
    <!#NetBIOS#!>                      = Node's NetBIOS name, e.g. SRVDDC01
    <!#DistinguishedName#!>, <!#DN#!>  = Node's x500 distinguished name, e.g. cn=srvddc01,dc=lab,dc=local
    <!#CommonName#!>, <!#CN#!>         = Node's x500 common name, e.g. cn=srvddc01
    <!#CvadVersion#!>                  = Full CVAD version number, e.g. 1912CU1
    <!#CvadVersionLower#!>             = Full lowercase CVAD version number, e.g. 1912cu1
    <!#CvadShortVersion#!>             = Shortened (no 'C') full CVAD version number, e.g. 1912U1
    <!#CvadShortVersionLower#!>        = Shortened (no 'C') full lowercase CVAD version number, e.g. 1912u1
    <!#CvadMajorVersion#!>             = CVAD major version number, e.g. 1912
    <!#CvadUpdateVersion#!>            = CVAD update version number, e.g 1
#>
@{
    AllNodes = @(
        @{
            NodeName                    = '*'
            PsDscAllowDomainUser        = $true
            PsDscAllowPlainTextPassword = $true
            RebootNodeIfNeeded          = $true
            ConfigurationMode           = 'ApplyOnly'
            AllowModuleOverwrite        = $true
            DebugMode                   = 'ForceModuleImport'
        }

        @{
            NodeName = 'SRVCX1912DDC01'
            Role = 'Controller','Studio'
        }
        @{
            NodeName = 'SRVCX1912DDC02'
            Role = 'Controller','Studio'
        }
        @{
            NodeName = 'SRVCX1912FAS01'
            Role = 'FAS'
        }
        @{
            NodeName = 'SRVCX1912FAS02'
            Role = 'FAS'
        }
        @{
            NodeName = 'SRVCX1912STF01'
            Role = 'Storefront'
        }
        @{
            NodeName = 'SRVCX1912STF02'
            Role = 'Storefront'
        }
    )
    NonNodeData = @{

        DscResourcePath = '\\srvfs01.lab.local\Software\DscSmbShare'

        ActiveDirectory = @{
            DomainName   = 'lab.local'
            CARootName   = 'lab-CONTROLLER-CA'
            CAServerFQDN = 'controller.lab.local'
            LDAPPort     = 3269
        }

        Citrix = @{

            XenDesktop = @{

                Version            = '1912'
                MediaRootPath      = '\\srvfs01.lab.local\Software\Image Build\Citrix' ## Needs to be accessible by the domain computer accounts

                Site = @{
                    SiteName       = 'CVAD<!#CvadMajorVersion#!>'
                    DatabaseServer = 'srvsql01.lab.local'
                    SiteDbName     = 'Citrix<!#CvadMajorVersion#!>Site'
                    LoggingDbName  = 'Citrix<!#CvadMajorVersion#!>Logging'
                    MonitorDbName  = 'Citrix<!#CvadMajorVersion#!>Monitor'
                    Licensing = @{
                        LicenseServer  = 'srvcls.lab.local'
                        LicenseProduct = 'MPS'
                        LicenseEdition = 'ENT'
                        LicenseModel   = 'Concurrent'
                    }
                    SiteConfig = @{
                        TrustRequestsSentToTheXmlServicePort = $true
                    }
                    Delegation = @{
                        Administrators = 'LAB\Domain Admins','LAB\CitrixAdmins'
                        Roles          = @(
                            @{
                                Name      = 'Full Administrator'
                                Members   = 'LAB\Domain Admins','LAB\CitrixAdmins'
                                RoleScope = 'All'
                            }
                        )
                    }
                }

                Certificate = @{
                    Subject             = '<!#DistinguishedName#!>'
                    KeyLength           = 2048
                    Exportable          = $true
                    ProviderName        = '"Microsoft RSA SChannel Cryptographic Provider"'
                    OID                 = '1.3.6.1.5.5.7.3.1'
                    KeyUsage            = '0xa0'
                    CertificateTemplate = 'WebServer'
                    SubjectAltName      = 'dns=<!#FQDN#!>&dns=xendesktop<!#CvadMajorVersion#!>.<!#DomainName#!>&dns=xendesktop.<!#DomainName#!>'
                    AutoRenew           = $true
                    FriendlyName        = 'XenDesktop SSL Certificate'
                    KeyType             = 'RSA'
                    RequestType         = 'CMC'
                }
            }

            Storefront = @{
                BaseHostname = 'storefront.lab.local'
                Certificate = @{
                    Subject             = '<!#DistinguishedName#!>'
                    KeyLength           = 2048
                    Exportable          = $true
                    ProviderName        = '"Microsoft RSA SChannel Cryptographic Provider"'
                    OID                 = '1.3.6.1.5.5.7.3.1'
                    KeyUsage            = '0xa0'
                    CertificateTemplate = 'WebServer'
                    SubjectAltName      = 'dns=<!#FQDN#!>&dns=storefront<!#CvadMajorVersion#!>.<!#DomainName#!>&dns=storefront.<!#DomainName#!>'
                    AutoRenew           = $true
                    FriendlyName        = 'Storefront SSL Certificate'
                    KeyType             = 'RSA'
                    RequestType         = 'CMC'
                }
                Hosts = @(
                    @{
                        HostName  = 'storefront.lab.local'
                        IPAddress = '127.0.0.1'
                    }
                )
                AuthenticationServices = @(
                    @{
                        FriendlyName           = 'Authentication'
                        VirtualPath            = '/Citrix/Authentication'
                        AuthenticationProtocol = 'ExplicitForms','CitrixAGBasic'
                        ClaimsFactoryName      = 'StandardClaimsFactory'
                    }
                    @{
                        FriendlyName           = 'FAS'
                        VirtualPath            = '/Citrix/FASAuthentication'
                        AuthenticationProtocol = 'ExplicitForms','CitrixAGBasic'
                        ClaimsFactoryName      = 'FASClaimsFactory'
                    }
                )
                Stores = @(
                    @{
                        StoreName        = 'Store'
                        AuthType         = 'Explicit'
                        AuthVirtualPath  = '/Citrix/Authentication'
                        StoreVirtualPath = '/Citrix/Store'
                        LockedDown       = $true
                        LaunchOptions = @{
                            VdaLogonDataProvider = ''
                        }
                        ExplicitCommonOptions = @{
                            Domains         = 'local', 'lab.local'
                            DefaultDomain   = 'lab.local'
                            HideDomainField = $true
                        }
                        Farm = @{
                            LoadBalance   = $true
                            TransportType = 'HTTPS'
                            Configuration = @{
                                PooledSockets = $true
                            }
                        }
                        WebReceiver = @{
                            Service = @{
                                ClassicReceiverExperience = $false
                                SessionStateTimeout       = 20
                                DefaultIISSite           = $true
                            }
                            UserInterface = @{
                                AutoLaunchDesktop                    = $true
                                MultiClickTimeout                    = 3
                                ShowAppsView                         = $true
                                ShowDesktopsView                     = $true
                                DefaultView                          = 'Auto'
                                ReceiverConfigurationEnabled         = $true
                                WorkspaceControlEnabled              = $true
                                WorkspaceControlAutoReconnectAtLogon = $true
                                WorkspaceControlLogoffAction         = 'None'
                                WorkspaceControlShowReconnectButton  = $false
                                WorkspaceControlShowDisconnectButton = $false
                            }
                        }
                    }
                    @{
                        StoreName        = 'FAS'
                        AuthType         = 'Explicit'
                        AuthVirtualPath  = '/Citrix/FASAuthentication'
                        StoreVirtualPath = '/Citrix/FAS'
                        LockedDown       = $true
                        LaunchOptions = @{
                            VdaLogonDataProvider = 'FASLogonDataProvider'
                        }
                        ExplicitCommonOptions = @{
                            Domains         = 'LOCAL', 'lab.local'
                            DefaultDomain   = 'lab.local'
                            HideDomainField = $true
                        }
                        Farm = @{
                            LoadBalance   = $true
                            TransportType = 'HTTPS'
                            Configuration = @{
                                PooledSockets = $true
                            }
                        }
                        WebReceiver = @{
                            Service = @{
                                ClassicReceiverExperience = $false
                                SessionStateTimeout       = 20
                                DefaultIISSite            = $false
                            }
                            UserInterface = @{
                                AutoLaunchDesktop                    = $true
                                MultiClickTimeout                    = 3
                                ShowAppsView                         = $true
                                ShowDesktopsView                     = $true
                                DefaultView                          = 'Auto'
                                ReceiverConfigurationEnabled         = $true
                                WorkspaceControlEnabled              = $true
                                WorkspaceControlAutoReconnectAtLogon = $true
                                WorkspaceControlLogoffAction         = 'None'
                                WorkspaceControlShowReconnectButton  = $false
                                WorkspaceControlShowDisconnectButton = $false
                            }
                        }
                        AccessGatewayVirtualServer = @{
                            LogonType            = 'DomainAndRSA'
                            GatewayUrl           = 'remote.lab.local'
                            SessionReliability   = $true
                            StasUseLoadBalancing = $true
                        }
                    }
                )
            }

            NetScaler = @{
                Defaults = @{
                    Hostname = 'srvcxns01'
                    Timezone = 'GMT+00:00-GMT-Europe/London'
                }
                Network = @{
                    DnsServers  = @('192.168.0.1','192.168.0.2') # Array
                    DnsSuffixes = @('lab.local') # Array
                }
                Authentication = @{
                    SAML = @{
                        Servers = @{
                            'okta' = @{
                                SAMLIDPCertName     = 'okta_lab_local'
                                SAMLSigningCertName = 'ns-server-certificate'
                                SAMLRedirectUrl     = 'https://lab_local.okta.com/app/citrixnetscalergateway_saml/tre83lkjewrb3xPOY6m0/sso/saml'
                                SAMLUserField       = 'Name ID'
                                SAMLIssuerName      = 'http://www.okta.com/tre83lkjewrb3xPOY6m0'
                                LogoutUrl           = 'https://lab_local.okta.com'
                                ForceAuthentication = 'ON'
                            }
                        }
                        Policies = @{
                            'policy_saml_okta' = @{
                                Action = 'okta';
                                Rule   = 'ns_true';
                            }
                        }
                    }
                }
                Certificates = @(
                    @{
                        Name              = 'lab-CONTROLLER-CA'
                        Path              = 'lab-CONTROLLER-CA.crt'
                        Format            = 'DER'
                    }
                    @{
                        Name              = 'ComodoAddTrustCA'
                        Path              = 'ComodoAddTrustCA.crt'
                        Format            = 'DER'
                    }
                    @{
                        Name              = 'ComodoRSADomainValidationSecureServerCA'
                        Path              = 'ComodoRSADomainValidationSecureServerCA.crt'
                        Format            = 'DER'
                        CACertificateName = 'ComodoAddTrustCA'
                    }
                    @{
                        Name              = 'remote_lab_local'
                        Path              = 'remote_lab_local.pfx'
                        Format            = 'PFX'
                        Password          = '<REDACTED>'
                        CACertificateName = 'ComodoRSADomainValidationSecureServerCA'
                    }
                ) 
                
                AccessGatewayVirtualServers = @{

                    'FAS' = @{ ## Links to Storefront Store\StoreName

                        VServerName     = 'vip_remote_lab_local_<!#CvadMajorVersion#!>'
                        IPAddress       = '192.168.0.100'
                        CertificateName = 'remote_lab_local'
                        Authentication  = 'ENABLED'
                        Theme           = 'X1'
                        SessionPolicies = @(
                            @{
                                Name        = 'policy_receiver_storefront<!#CvadVersionLower#!>_lab_local'
                                ProfileName = 'profile_storefront<!#CvadVersionLower#!>_lab_local'
                                Rule        = 'REQ.HTTP.HEADER User-Agent CONTAINS CitrixReceiver || REQ.HTTP.HEADER Referer NOTEXISTS'
                            }
                            @{
                                Name        = 'policy_web_storefront<!#CvadVersionLower#!>_lab_local'
                                ProfileName = 'profile_storefront<!#CvadVersionLower#!>_lab_local'
                                Rule        = 'REQ.HTTP.HEADER User-Agent NOTCONTAINS CitrixReceiver && REQ.HTTP.HEADER Referer EXISTS'
                            }
                        )
                        SessionProfiles = @(
                            @{
                                Name                       = 'profile_storefront<!#CvadVersionLower#!>_lab_local'
                                TransparentInterception    = 'OFF'
                                SplitTunnel                = 'OFF'
                                SSO                        = 'ON'
                                NTDomain                   = 'LOCAL'
                                DefaultAuthorizationAction = 'ALLOW'
                                IcaProxy                   = 'ON'
                                ClientlessVpnMode          = 'OFF'
                                ClientChoices              = 'OFF'
                                WIHome                     = 'https://storefront<!#CvadVersionLower#!>.lab.local/Citrix/FASWeb'
                                StoreFrontUrl              = 'https://storefront<!#CvadVersionLower#!>.lab.local'
                            }
                        )
                        Bindings = @{
                            Authentication = @{
                                SAML = @('policy_saml_okta')
                            }
                            SessionPolicies = @(
                                @{
                                    Name     = 'policy_receiver_storefront<!#CvadVersionLower#!>_lab_local'
                                    Priority = 100
                                }
                                @{
                                    Name     = 'policy_web_storefront<!#CvadVersionLower#!>_lab_local'
                                    Priority = 110
                                }
                            )
                        }
                    }
                }
            }
        }
    }
}
