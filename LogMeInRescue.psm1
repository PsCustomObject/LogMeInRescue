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
    
    .NOTES
        Additional information about the function.
#>
    
    [CmdletBinding(PositionalBinding = $true)]
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
    [string]$returnCode = $apiProxy.requestAuthCode($apiUser, $apiPassword, [ref]$authCodeRef)
    
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
        
        .PARAMETER AuthCode
            A string representing the AuthCode used to authenticate against LogMeIn Rescue API.
        
        .PARAMETER NodeId
            An integer value representing the NodeID of a user for whcih properties should be retrieved.
        
        .EXAMPLE
            PS C:\> Get-RescueUser -AuthCode 'Value1' -NodeId $value2
    #>
    
    [OutputType([pscustomobject])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $AuthCode,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [int]
        $NodeId
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
    
    # Request auth code
    [string]$returnCode = $apiProxy.getUser_v2($NodeId, $AuthCode, $resultRef)
    
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