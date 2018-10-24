
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
                Write-Error 'This system is not supported.'
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
        [securestring]
        $Password
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
                Write-Error 'This system is not supported.'
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
            throw 'Failed to get BIOS setting.'
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
        [securestring]
        $Password
    )

    Begin {
        if ($Password) {
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            $PasswordParameter = ($plainPassword, 'ascii', 'us') -join ','
        }

        $SetBios = Get-WmiObject -Class Lenovo_SetBiosSetting -Namespace root\wmi -ErrorAction Continue
        $SaveBios = Get-WmiObject -Class Lenovo_SaveBiosSettings -Namespace root\wmi -ErrorAction Continue
        $DiscardBios = Get-WmiObject -Class Lenovo_DiscardBiosSettings -Namespace root\wmi -ErrorAction Continue

        if (($null -eq $SetBios) -or ($null -eq $DiscardBios) -or ($null -eq $SaveBios)) {
            throw 'Failed to get BIOS setting.'
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
                Write-Verbose 'The BIOS setting is changed successfully.'
            }
            else {
                throw ('Error occurred in changing BIOS: {0}' -f $SetResult.return)
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
                Write-Verbose 'The BIOS setting is saved successfully.'
            }
            else {
                throw ('Error occurred in saving BIOS: {0}' -f $SaveResult.return)
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
                Write-Verbose 'Discarding BIOS setting.'
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
            throw 'Failed to get BIOS setting.'
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
        [securestring]
        $Password
    )

    Begin {
        if ($Password) {
            $PasswordEncoding = '<utf-16/>'
            $private:bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($private:bstr)
            $PasswordParameter = $PasswordEncoding + $plainPassword
        }

        $BiosInterface = Get-WmiObject -Class HP_BIOSSettingInterface -Namespace root\HP\InstrumentedBIOS -ErrorAction Continue

        if ($null -eq $BiosInterface) {
            throw 'Failed to get BIOS setting.'
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
            Write-Verbose 'The BIOS setting is saved successfully.'
        }
        else {
            throw ('Error occurred in saving BIOS: {0}' -f $ResultMessage)
        }
    }

    End {
    }
}

Export-ModuleMember -Function @(
    'Get-BiosSettings',
    'Set-BiosSettings'
)
