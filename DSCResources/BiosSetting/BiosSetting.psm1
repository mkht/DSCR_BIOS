
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
            Write-Error 'Bios setting item not found.'
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
            $SetParam.Credential = $Credential
        }

        Set-BiosSettings @SetParam -ErrorAction Stop

        #Require reboot
        if (-not $NoRestart) {
            $global:DSCMachineStatus = 1
        }
    }
    catch {
        Write-Error -Exception $_.Exception
    }
}
#endregion Set-TargetResource


function Get-BiosSettings {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Item
    )

    Begin {
        $WmiBios = Get-WmiObject -Class Win32_BIOS
    }

    Process {
        switch ($WmiBios.Manufacturer) {
            'Lenovo' { 
                Get-LenovoBiosSettings @PSBoundParameters
            }

            'HP' {
                Get-HPBiosSettings @PSBoundParameters
            }
            Default {
                Write-Error 'not compatible'
            }
        }
    }

    End {}
}


function Set-BiosSettings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Item,

        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyString()]
        [string]
        $Value,

        [Parameter(Mandatory = $false)]
        [pscredential]
        $Credential
    )

    Begin {
        $WmiBios = Get-WmiObject -Class Win32_BIOS
    }

    Process {
        switch ($WmiBios.Manufacturer) {
            'Lenovo' { 
                Set-LenovoBiosSettings @PSBoundParameters
            }

            'HP' {
                Set-HPBiosSettings @PSBoundParameters
            }
            Default {
                Write-Error 'not compatible'
            }
        }
    }

    End {}
}


function Get-LenovoBiosSettings {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Item
    )

    Begin {
        $BiosObj = Get-WmiObject -Class Lenovo_BiosSetting -Namespace root\wmi -ErrorAction Continue |`
            Where-Object {-not [string]::IsNullOrWhiteSpace($_.CurrentSetting)} |`
            Select-Object -Property @(
            @{
                Name       = 'Item'
                Expression = {($_.CurrentSetting -split ',')[0]}
            },
            @{
                Name       = 'Value'
                Expression = {($_.CurrentSetting -split ',')[1]}
            }
        )

        if ($null -eq $BiosObj) {
            throw 'Bios wmi not found.'
        }
    }

    Process {
        if ($Item) {
            $BiosObj | Where-Object {$_.Item -ceq $Item}
        }
        else {
            $BiosObj
        }
    }
}


function Set-LenovoBiosSettings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Item,

        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyString()]
        [string]
        $Value,

        [Parameter(Mandatory = $false)]
        [pscredential]
        $Credential
    )

    Begin {
        if ($Credential) {
            $PasswordParameter = ($Credential.GetNetworkCredential().Password, 'ascii', 'us') -join ','
        }

        $SetBios = Get-WmiObject -Class Lenovo_SetBiosSetting -Namespace root\wmi -ErrorAction Continue
        $SaveBios = Get-WmiObject -Class Lenovo_SaveBiosSettings -Namespace root\wmi -ErrorAction Continue
        $DiscardBios = Get-WmiObject -Class Lenovo_DiscardBiosSettings -Namespace root\wmi -ErrorAction Continue

        if (($null -eq $SetBios) -or ($null -eq $DiscardBios) -or ($null -eq $SaveBios)) {
            throw 'Bios wmi not found'
        }
    }

    Process {
        [bool]$IsSet = $false
        [bool]$IsSaved = $false

        try {
            #Set 
            [string[]]$SetParameterArray = @($Item, $Value)
            if ($PasswordParameter) {
                $SetParameterArray += $PasswordParameter
            }

            [string]$SetParameterString = $SetParameterArray -join ','

            $SetResult = $SetBios.SetBiosSetting($SetParameterString)

            if ($SetResult.return -eq 'Success') {
                $IsSet = $true
                Write-Verbose 'Set Success'
            }
            else {
                throw ('Error Set: {0}' -f $SetResult.return)
            }

            # Save
            [string[]]$SaveParameterArray = @()
            if ($PasswordParameter) {
                $SaveParameterArray += $PasswordParameter
            }
    
            [string]$SaveParameterString = $SaveParameterArray -join ','

            $SaveResult = $SaveBios.SaveBiosSettings($SaveParameterString)
    
            if ($SaveResult.return -eq 'Success') {
                $IsSaved = $true
                Write-Verbose 'Success Save'
            }
            else {
                throw ('Error Save: {0}' -f $SaveResult.return)
            }
        }
        catch {
            if ($IsSet -and (-not $IsSaved)) {
                #Discard changes
                [string[]]$DiscardParameterArray = @()
                if ($PasswordParameter) {
                    $DiscardParameterArray += $PasswordParameter
                }
    
                [string]$DiscardParameterString = $DiscardParameterArray -join ','
                $null = $DiscardBios.DiscardBiosSettings($DiscardParameterString)
            }

            throw
        }
    }

    End {
    }
}


function Get-HPBiosSettings {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Item
    )

    Begin {
        $BiosObj = Get-WmiObject -Class HP_BIOSSetting -Namespace root\HP\InstrumentedBIOS -ErrorAction Continue |`
            Where-Object {-not [string]::IsNullOrWhiteSpace($_.Name)} |`
            Select-Object -Property @(
            @{
                Name       = 'Item'
                Expression = {$_.Name}
            },
            @{
                Name       = 'Value'
                Expression = {
                    if ($_.Value -match '\*') {
                        ($_.Value -split ',') -match '\*' -replace '\*', ''
                    }
                    else {
                        $_.Value
                    }
                }
            }
        )

        if ($null -eq $BiosObj) {
            throw 'no wmi found'
        }
    }

    Process {
        if ($Item) {
            $BiosObj | Where-Object {$_.Item -ceq $Item}
        }
        else {
            $BiosObj
        }
    }
}


function Set-HPBiosSettings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Item,

        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyString()]
        [string]
        $Value,

        [Parameter(Mandatory = $false)]
        [pscredential]
        $Credential
    )

    Begin {
        if ($Credential) {
            $PasswordEncoding = '<utf-16/>'
            $PasswordParameter = $PasswordEncoding + $Credential.GetNetworkCredential().Password
        }

        $BiosInterface = Get-WmiObject -Class HP_BIOSSettingInterface -Namespace root\HP\InstrumentedBIOS -ErrorAction Continue

        if ($null -eq $BiosInterface) {
            throw 'Bios wmi not found'
        }
    }

    Process {
        if ($PasswordParameter) {
            $SetResult = $BiosInterface.SetBIOSSetting($Item, $Value, $PasswordParameter)
        }
        else {
            $SetResult = $BiosInterface.SetBIOSSetting($Item, $Value)
        }

        switch ($SetResult.Return) {
            0 { $ResultMessage = 'Success' }
            1 { $ResultMessage = 'Not Supported' }
            2 { $ResultMessage = 'Unspecified Error' }
            3 { $ResultMessage = 'Timeout' }
            4 { $ResultMessage = 'Failed' }
            5 { $ResultMessage = 'Invalid Parameter' }
            6 { $ResultMessage = 'Access Denied' }
            Default { $ResultMessage = 'Unexpected Error' }
        }

        if ($ResultMessage -eq 'Success') {
            Write-Verbose 'Set Success'
        }
        else {
            throw ('Error Set: {0}' -f $ResultMessage)
        }
    }

    End {
    }
}


Export-ModuleMember -Function *-TargetResource
