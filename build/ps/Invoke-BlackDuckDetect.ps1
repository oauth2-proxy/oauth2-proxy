param(
    $ProjectName = "EDI-FoundationLayer",
    $ProjectVersionName = "1.0",
    $SourcePath,
    $BlackduckUrl = "https://blackduck.philips.com/",
    $ApiToken = "OWFkOWM0NGMtM2FlMy00ODFiLThjMTctM2I1OTdkMTY2MTQ2OmNlMGI4NmNhLWRjMzAtNGU0Yy04NTIwLWEzZDI5NDFlNjdkMg==",
    $ProxyHost = "apac.zscaler.philips.com",
    $ProxyPort = "10015",
    $ProxyIgnoreHosts = "blackduck.philips.com"

)


[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$detectScriptUrl = "https://detect.synopsys.com/detect.ps1"
$detectScriptLocal = "$PSScriptRoot\detect.ps1"
    
Invoke-WebRequest -Uri $detectScriptUrl -Method Get -OutFile $detectScriptLocal

Import-Module $detectScriptLocal 
Detect --detect.project.name=$ProjectName --detect.project.version.name=$ProjectVersionName --detect.source.path=$SourcePath --blackduck.url=$BlackduckUrl --blackduck.trust.cert=true --blackduck.api.token=$ApiToken --blackduck.proxy.host=$ProxyHost --blackduck.proxy.port=$ProxyPort --blackduck.proxy.ignored.hosts=$ProxyIgnoreHosts --detect.blackduck.signature.scanner.individual.file.matching=ALL --detect.detector.search.depth=6
