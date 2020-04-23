@{
    ModuleVersion = '0.1.0.0'
    RootModule = 'WinTweaks.psm1'
    NestedModules = @(
        'modules\Apps.psm1',
        'modules\Explorer.psm1',
        'modules\Network.psm1',
        'modules\Privacy.psm1',
        'modules\Security.psm1',
        'modules\Server.psm1',
        'modules\Service.psm1',
        'modules\Shell.psm1',
        'modules\Unpin.psm1'
    )
    FunctionsToExport = @(
        'WinTweaks'
    )
}
