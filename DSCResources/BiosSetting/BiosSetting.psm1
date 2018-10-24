
#region Get-TargetResource
function Get-TargetResource {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Item,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]
        $Value
    )

    try {
        $CurrentBiosSetting = Get-BiosSettings -Item $Item -ErrorAction Stop
        if ($null -eq $CurrentBiosSetting) {
            Write-Error 'Failed to get BIOS setting.'
        }
        else {
            @{
                Item  = $CurrentBiosSetting.Item
                Value = $CurrentBiosSetting.Value
            }
        }
    }
    catch {
        Write-Error -Exception $_.Exception
    }
}
#endregion Get-TargetResource


#region Test-TargetResource
function Test-TargetResource {
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Item,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]
        $Value,

        [Parameter(Mandatory = $false)]
        [pscredential]
        $Credential,

        [Parameter(Mandatory = $false)]
        [bool]
        $NoRestart = $false
    )

    $CurrentBiosSetting = Get-TargetResource -Item $Item -Value $Value -ErrorAction Stop

    if ($CurrentBiosSetting.Value -ceq $Value) {
        return $true
    }
    else {
        return $false
    }
}
#endregion Test-TargetResource


#region Set-TargetResource
function Set-TargetResource {
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Item,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]
        $Value,

        [Parameter(Mandatory = $false)]
        [pscredential]
        $Credential,

        [Parameter(Mandatory = $false)]
        [bool]
        $NoRestart = $false
    )

    try {
        $SetParam = @{
            Item  = $Item
            Value = $Value
        }

        if ($Credential) {
            $SetParam.Password = $Credential.Password
        }

        Set-BiosSettings @SetParam -ErrorAction Stop

        #Require reboot
        if (-not $NoRestart) {
            Write-Verbose 'It is necessary to restart the machine.'
            $global:DSCMachineStatus = 1
        }
    }
    catch {
        Write-Error -Exception $_.Exception
    }
}
#endregion Set-TargetResource


Export-ModuleMember -Function *-TargetResource
