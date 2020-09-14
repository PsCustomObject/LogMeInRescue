function Get-RescueAuthToken
{
<#
    .SYNOPSIS
        Cmdlet is used to request a new Authentication Token to interact with LogMeInRescue API.
    
    .DESCRIPTION
        Cmdlet is used to request a new Authentication Token to interact with LogMeInRescue API.
    
    .PARAMETER UserName
        A string representing the username used to authenticated against LogMeIn Rescue API.
    
    .PARAMETER Password
        A string representing the password used to authenticated against LogMeIn Rescue API.
    
    .EXAMPLE
        PS C:\> Get-RescueAuthToken -UserName 'Value1' -Password 'Value2'
#>
    
    [CmdletBinding(PositionalBinding = $true,
                   SupportsPaging = $false,
                   SupportsShouldProcess = $false)]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $UserName,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Password
    )
    
    # Define PsReference object
    [ref]$authCodeRef = [string]::Empty
    
    # Define endpoint URL
    [string]$apiUrl = 'https://secure.logmeinrescue.com/API/API.asmx'
    
    # Initialize proxy object
    $paramNewWebServiceProxy = @{
        Uri       = $apiUrl
        Namespace = 'requestAuthCode'
    }
    
    $apiProxy = New-WebServiceProxy @paramNewWebServiceProxy
    
    # Request auth code
    [string]$returnCode = $apiProxy.requestAuthCode($UserName, $Password, [ref]$authCodeRef)
    
    if ($returnCode -ne 'requestAuthCode_OK')
    {
        throw $returnCode
    }
    else
    {
        return $authCodeRef.Value
    }
}

function Get-RescueUser
{
<#
    .SYNOPSIS
        Get users details in LogMeIn Rescue
    
    .DESCRIPTION
        Cmdelt is used to retrieve information about any user configured in the LogMeIn Rescue portal.
    
    .PARAMETER NodeId
        An integer value representing the NodeID of a user for which properties should be retrieved.
    
    .PARAMETER UserEmail
        A string representing the email of a user which properties should be retrieved.
    
    .PARAMETER AuthCode
        A string representing the AuthCode used to authenticate against LogMeIn Rescue API.
    
    .EXAMPLE
        PS C:\> Get-RescueUser -AuthCode 'Value1' -NodeId $value2
    
    .OUTPUTS
        System.Management.Automation.PSObject
#>
    
    [CmdletBinding(DefaultParameterSetName = 'Email',
                   PositionalBinding = $true,
                   SupportsPaging = $false,
                   SupportsShouldProcess = $false)]
    [OutputType([pscustomobject])]
    param
    (
        [Parameter(ParameterSetName = 'NodeId',
                   Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [int]
        $NodeId,
        [Parameter(ParameterSetName = 'Email',
                   Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $UserEmail,
        [Parameter(ParameterSetName = 'Email',
                   Mandatory = $true)]
        [Parameter(ParameterSetName = 'NodeId',
                   Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $AuthCode
    )
    
    # Define PsReference object
    [ref]$resultRef = $null
    
    # Define endpoint URL
    [string]$apiUrl = 'https://secure.logmeinrescue.com/API/API.asmx'
    
    # Initialize proxy object
    $paramNewWebServiceProxy = @{
        Uri       = $apiUrl
        Namespace = 'getUser_v3'
    }
    
    $apiProxy = New-WebServiceProxy @paramNewWebServiceProxy
    
    switch ($PSCmdlet.ParameterSetName)
    {
        'NodeId'
        {
            # Get user details
            [string]$returnCode = $apiProxy.getUser_v2($NodeId, $AuthCode, $resultRef)
            
            break
        }
        'Email'
        {
            # Get user details
            [string]$returnCode = $apiProxy.getUser_v3($null, $UserEmail, $AuthCode, $resultRef)
            
            break
        }
    }
    
    if ($returnCode -ne 'getUser_OK')
    {
        throw $returnCode
    }
    else
    {
        # Prepare return data
        $returnData = [pscustomobject]@{
            'Node ID' = $resultRef.'Value'.'iNodeID'
            'Name'    = $resultRef.'Value'.'sName'
            'Email'   = $resultRef.'Value'.'sEmail'
            'Nick Name' = $resultRef.'Value'.'sNick'
            'SSO Username' = $resultRef.'Value'.'sSSOID'
            'Account Type' = $resultRef.'Value'.'eType'
            'Description' = $resultRef.'Value'.'sDescription'
            'Account Holder' = $resultRef.'Value'.'bAccountHolder'
            'Mobile addon Enabled' = $resultRef.'Value'.'hasMobileAddon'
            'RPAT addon Enabled' = $resultRef.'Value'.'hasRPATAddon'
            'Status'  = $resultRef.'Value'.'eStatus'
        }
        
        return $returnData
    }
}

function Get-RescueHierarchy
{
<#
    .SYNOPSIS
        Cmdlet will return an array with all nodes defined in rescue console.
    
    .DESCRIPTION
        Cmdlet will return an array with all nodes defined in rescue console indipendently of the node type and their status.
    
    .PARAMETER AuthCode
        A string representing the AuthCode used to authenticate against LogMeIn Rescue API.
    
    .EXAMPLE
        PS C:\> Get-RescueHierarchy -AuthCode 'Value1'
#>
    
    [CmdletBinding(SupportsPaging = $false,
                   SupportsShouldProcess = $false)]
    [OutputType([array])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $AuthCode
    )
    
    # Define PsReference object
    [ref]$resultRef = $null
    
    # Define endpoint URL
    [string]$apiUrl = 'https://secure.logmeinrescue.com/API/API.asmx'
    
    # Initialize proxy object
    $paramNewWebServiceProxy = @{
        Uri       = $apiUrl
        Namespace = 'getUser_v2'
    }
    
    $apiProxy = New-WebServiceProxy @paramNewWebServiceProxy
    
    # Get hierarchy details
    [string]$returnCode = $apiproxy.getHierarchy_v2($authToken, $false, $false, $false, $resultRef)
    
    if ($returnCode -ne 'getHierarchy_OK')
    {
        throw $returnCode
    }
    else
    {
        return $resultRef.Value
    }
}

function Set-RescueUser
{
<#
    .SYNOPSIS
        Cmdlet updates the properties of a user in the company hierarchy.
    
    .DESCRIPTION
        Cmdlet updates the properties of a user in the company hierarchy.
    
    .PARAMETER NodeId
        An integer representing the Node ID of the user which is being modified.
    
    .PARAMETER UserName
        A string representing the name assigned to the user.
    
    .PARAMETER Description
        A string representing the the descripion that will be used for the user.
    
    .PARAMETER Email
        A string representing the email assigned to the user.
    
    .PARAMETER SSOUserName
        A string representing the username, in email format, that will be configured for user configured for Single Sign-On.
    
    .PARAMETER UserPassword
        A string representing the password that will be configured for the user.
    
    .PARAMETER OldUserPassword
        A string representing the old password for the user.
    
    .PARAMETER UserStatus
        A string representing the status of the user. Enabled or Disabled.
    
    .PARAMETER MobileAddOn
        A boolean value representing MobileAddOn configuration for the user.
    
    .PARAMETER RPATAddon
        A boolean value representing RPATAddon configuration for the user.
    
    .PARAMETER UserNick
        A string representing the NickName configured for the user.
        
        Parameter is not visible in Admin Console.
    
    .PARAMETER AuthCode
        A string representing the AuthCode used to authenticate against LogMeIn Rescue API.
    
    .EXAMPLE
        PS C:\> Set-RescueUser -AuthCode 'Value1' -NodeId $value2 -UserName 'Value3' -Email 'Value4' -UserStatus Enabled -MobileAddOn True -RPATAddon $value7
#>
    
    [CmdletBinding(SupportsPaging = $false,
                   SupportsShouldProcess = $false)]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [int]
        $NodeId,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $UserName,
        [ValidateNotNullOrEmpty()]
        [string]
        $Description = $null,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Email,
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SSOUserName = $null,
        [ValidateNotNullOrEmpty()]
        [string]
        $UserPassword = $null,
        [ValidateNotNullOrEmpty()]
        [string]
        $OldUserPassword = $null,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Enabled', 'Disabled', IgnoreCase = $true)]
        [string]
        $UserStatus,
        [Parameter(Mandatory = $true)]
        [ValidateSet('True', 'False', IgnoreCase = $true)]
        [string]
        $MobileAddOn,
        [Parameter(Mandatory = $true)]
        [bool]
        $RPATAddon,
        [ValidateNotNullOrEmpty()]
        [string]
        $UserNick = $null,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $AuthCode
    )
    
    # Define endpoint URL
    [string]$apiUrl = 'https://secure.logmeinrescue.com/API/API.asmx'
    
    # Initialize proxy object
    $paramNewWebServiceProxy = @{
        Uri       = $apiUrl
        Namespace = 'setUser_v2'
    }
    
    $apiProxy = New-WebServiceProxy @paramNewWebServiceProxy
    
    if (($UserStatus -eq 'Enabled') -and
        (([string]::IsNullOrEmpty($UserPassword) -eq $true) -and
            ([string]::IsNullOrEmpty($SSOUserName) -eq $true)))
    {
        throw 'Cannot enable account if password is empty or no SSO username is configured'
    }
    
    # Configure user properties
    [string]$returnCode = $apiProxy.setUser_V2($NodeId, $UserName, $UserNick, $Email,
        $SSOUserName, $UserPassword, $UserPassword,
        $OldUserPassword, $UserStatus, $Description, $MobileAddOn,
        $RPATAddon, $AuthCode)
    
    if ($returnCode -ne 'setUser_OK')
    {
        throw $returnCode
    }
}

function New-RescueUser
{
<#
    .SYNOPSIS
        Cmdlet will create a new LogMeIn Rescue user.
    
    .DESCRIPTION
        Cmdlet will create a new LogMeIn Rescue user (technician, administrator, or master administrator) in the company hierarchy (Organization Tree).
    
    .PARAMETER ParentNodeId
        An integer representing the NodeID of an existing group in the company hierarchy.
    
    .PARAMETER AuthCode
        A string representing the AuthCode used to authenticate against LogMeIn Rescue API.
    
    .EXAMPLE
        PS C:\> New-RescueUser -AuthCode 'Value1' -ParentNodeId $value2
#>
    
    [CmdletBinding(PositionalBinding = $true,
                   SupportsPaging = $false,
                   SupportsShouldProcess = $false)]
    [OutputType([int])]
    param
    (
        [Parameter(Mandatory = $true)]
        [int]
        $ParentNodeId,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $AuthCode
    )
    
    # Define PsReference object
    [ref]$resultRef = $null
    
    # Define endpoint URL
    [string]$apiUrl = 'https://secure.logmeinrescue.com/API/API.asmx'
    
    # Initialize proxy object
    $paramNewWebServiceProxy = @{
        Uri       = $apiUrl
        Namespace = 'createUser'
    }
    
    $apiProxy = New-WebServiceProxy @paramNewWebServiceProxy
    
    # Create user
    [string]$returnCode = $apiProxy.createUser($ParentNodeId, $AuthCode, $resultRef)
    
    if ($returnCode -ne 'createUser_OK')
    {
        throw $returnCode
    }
    else
    {
        return $resultRef.Value
    }
}

function Move-RescueNode
{
<#
    .SYNOPSIS
        Cmdlet will move a node from one parent node to another in the company hierarchy.
    
    .DESCRIPTION
        Cmdlet will move a node from one parent node to another in the company hierarchy.
    
    .PARAMETER NodeId
        An integer representing the NodeID of a user or group in the company hierarchy.
    
    .PARAMETER TargetNodeId
        An integer representing the NodeID of an existing group in the company hierarchy which will be the new parent node of the object being moved.
    
    .PARAMETER AuthCode
        A string representing the AuthCode used to authenticate against LogMeIn Rescue API.
    
    .EXAMPLE
        PS C:\> Move-RescueNode -AuthCode 'value1' -NodeId $NodeId -TargetNodeId $TargetNodeId
#>
    
    [CmdletBinding(PositionalBinding = $true,
                   SupportsPaging = $false,
                   SupportsShouldProcess = $false)]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true)]
        [int]
        $NodeId,
        [Parameter(Mandatory = $true)]
        [int]
        $TargetNodeId,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $AuthCode
    )
    
    # Define endpoint URL
    [string]$apiUrl = 'https://secure.logmeinrescue.com/API/API.asmx'
    
    # Initialize proxy object
    $paramNewWebServiceProxy = @{
        Uri       = $apiUrl
        Namespace = 'moveNode'
    }
    
    $apiProxy = New-WebServiceProxy @paramNewWebServiceProxy
    
    # Move node
    [string]$returnCode = $apiProxy.moveNode($TargetNodeId, $NodeId, $AuthCode)
    
    if ($returnCode -ne 'moveNode_OK')
    {
        throw $returnCode
    }
}

function Remove-RescueNode
{
<#
    .SYNOPSIS
        Cmdlet will delete a node from the company hierarchy.
    
    .DESCRIPTION
        Cmdlet will delete a node from the company hierarchy.
    
    .PARAMETER NodeId
        An integer representing the NodeID of a user or group in the company hierarchy.
    
    .PARAMETER AuthCode
        A string representing the AuthCode used to authenticate against LogMeIn Rescue API.
    
    .EXAMPLE
        PS C:\> Remove-RescueNode -AuthCode 'value1' -NodeId $NodeId
#>
    
    [CmdletBinding(PositionalBinding = $true,
                   SupportsPaging = $false,
                   SupportsShouldProcess = $false)]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true)]
        [int]
        $NodeId,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $AuthCode
    )
    
    # Define endpoint URL
    [string]$apiUrl = 'https://secure.logmeinrescue.com/API/API.asmx'
    
    # Initialize proxy object
    $paramNewWebServiceProxy = @{
        Uri       = $apiUrl
        Namespace = 'deleteNode'
    }
    
    $apiProxy = New-WebServiceProxy @paramNewWebServiceProxy
    
    # Move node
    [string]$returnCode = $apiProxy.deleteNode($NodeId, $AuthCode)
    
    if ($returnCode -ne 'deleteNode_OK')
    {
        throw $returnCode
    }
}

function Set-RescueUserStatus
{
<#
    .SYNOPSIS
        Cmdlet will change the status of a node in the company hierarchy.
    
    .DESCRIPTION
        Cmdlet will change the status of a node in the company hierarchy.
    
    .PARAMETER NodeId
        An integer representing the NodeID of a user or group in the company hierarchy.
    
    .PARAMETER AccountStatus
        A string representing the desired status of the node. Possible values are:
        
        - Enabled
        - Disabled
        
        If node has no password and no SSO username is configured for the node an error will be thrown.
    
    .PARAMETER AuthCode
        A string representing the AuthCode used to authenticate against LogMeIn Rescue API.
#>
    
    [CmdletBinding(PositionalBinding = $true,
                   SupportsPaging = $false,
                   SupportsShouldProcess = $false)]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true)]
        [int]
        $NodeId,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Enabled', 'Disabled', IgnoreCase = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $AccountStatus,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $AuthCode
    )
    
    # Define endpoint URL
    [string]$apiUrl = 'https://secure.logmeinrescue.com/API/API.asmx'
    
    # Initialize proxy object
    $paramNewWebServiceProxy = @{
        Uri       = $apiUrl
        Namespace = 'setUserStatus_v7_1'
    }
    
    $apiProxy = New-WebServiceProxy @paramNewWebServiceProxy
    
    # Update node status
    [string]$returnCode = $apiProxy.setUserStatus_v7_1($NodeId, $AccountStatus, $AuthCode)
    
    if ($returnCode -ne 'OK')
    {
        throw $returnCode
    }
}