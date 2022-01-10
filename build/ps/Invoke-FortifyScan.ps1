param(
    $FortifyProjectId = "edifoundation-oauth2proxy",
    $FortifyVersionId = "Main",
    $FortifyBuildId = "fortify_fl",
    $FortifyFprPath = "$PSScriptRoot\$FortifyProjectId.$FortifyVersionId.fpr",
    $PublishURL = "https://fortify.philips.com/ssc",
    $PublishAuthToken = "785de478-dc2d-4829-959c-ea5cb8cd1adc",
    $RepositoryRoot = "$PSScriptRoot\..\..\"
)

function Invoke-VswhereDownload (
    [string]$Uri = "https://github.com/microsoft/vswhere/releases/download/2.8.4/vswhere.exe",
    [string]$Outfile = "$PSScriptRoot\vswhere.exe"
) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Output "downloading from '$Uri' to '$Outfile'"
    Write-Output "please wait..."
    Invoke-WebRequest -Uri $Uri -OutFile $Outfile
}

try {
    $RepositoryRoot = [System.IO.Path]::GetFullPath($RepositoryRoot)

    Invoke-VswhereDownload -Outfile "$PSScriptRoot\vswhere.exe"
    & "$PSScriptRoot\vswhere.exe" -version 16.0 -property installationPath > "$PSScriptRoot\vswhereproductpath.txt"
    $vspath = Get-Content -Path "$PSScriptRoot\vswhereproductpath.txt"
    $env:Path = "$env:Path;$vspath\MSBuild\Current\Bin\"

    & sourceanalyzer -b $FortifyBuildId -clean -logfile "$PSScriptRoot\fortify-clean.txt"
    
    & dotnet restore "$RepositoryRoot\contrib\oauth2-proxy_autocomplete.sln" -s "https://api.nuget.org/v3/index.json" --ignore-failed-sources

    & dotnet restore "$RepositoryRoot\contrib\oauth2-proxy_autocomplete.sln"
    & sourceanalyzer -b $FortifyBuildId msbuild.exe "$RepositoryRoot\contrib\oauth2-proxy_autocomplete.sln" /t:rebuild /p:Configuration=Release /p:Platform="Any CPU" /p:TreatWarningsAsErrors=false 

    & sourceanalyzer -b $FortifyBuildId -Xmx8G -scan -f $FortifyFprPath -logfile "$PSScriptRoot\fortify-scan.txt"

    #Upload fpr reports to fortify server

    Write-Output "Uploading '$FortifyFprPath' of '$FortifyProjectId' with version '$FortifyVersionId' to '$PublishURL'"
    & cmd /c fortifyclient.bat -url $PublishURL -authtoken $PublishAuthToken uploadFPR -file $FortifyFprPath -application $FortifyProjectId -applicationVersion "$FortifyVersionId"

    Write-Output "Completed Fortify scan"
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Error $ErrorMessage
    Write-Output $ErrorMessage
    exit -1
}
