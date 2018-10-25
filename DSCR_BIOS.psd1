@{
    ModuleVersion        = '0.0.1'
    RootModule           = 'DSCR_BIOS.psm1'
    GUID                 = 'b4310aa2-4036-49bd-a741-df85ea60d5bd'
    Author               = 'mkht'
    CompanyName          = ''
    Copyright            = '(c) 2018 mkht. All rights reserved.'
    Description          = ''
    PowerShellVersion    = '4.0'
    FunctionsToExport    = @(
        'Get-BiosSettings',
        'Set-BiosSettings',
        'Set-BiosPassword'
    )
    CmdletsToExport      = @()
    VariablesToExport    = '*'
    AliasesToExport      = @()
    DscResourcesToExport = @('BiosSetting')
    PrivateData          = @{
        PSData = @{
            Tags       = ('')
            LicenseUri = ''
            ProjectUri = ''
            # ReleaseNotes = ''
        }
    }
}
