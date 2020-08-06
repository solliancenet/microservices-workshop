Param (
  [Parameter(Mandatory = $true)]
  [string]
  $azureUsername,

  [string]
  $azurePassword,

  [string]
  $azureTenantID,

  [string]
  $azureSubscriptionID,

  [string]
  $odlId,
    
  [string]
  $deploymentId
)

function LoginGitWindows($password)
{
    $wshell.AppActivate('Sign in to your account')
    $wshell.sendkeys("{TAB}{ENTER}");
    $wshell.sendkeys($password);
    $wshell.sendkeys("{ENTER}");
}

function ExecuteRemoteCommand($ip, $password, $cmd, $sleep, $isInitial)
{
    if ($isInitial -or $cmd.contains("`r"))
    {
        $argumentlist = "plink.exe -t -ssh -l adminfabmedical -pw `"$password`" $ip";
    }
    else
    {
        $argumentlist = "plink.exe -t -ssh -l adminfabmedical -pw `"$password`" $ip `"$cmd`"";
    }

    start-process "cmd.exe"

    start-sleep 5;

    $wshell = New-Object -ComObject wscript.shell;

    $wshell.AppActivate('cmd.exe');
    $wshell.SendKeys($argumentlist)
    $wshell.SendKeys("{ENTER}")
    
    if ($isinitial)
    {
        start-sleep 2;
        $wshell.SendKeys("y")
        $wshell.SendKeys("{ENTER}")
    }

    if ($argumentlist.contains("-t") -and $cmd.contains("sudo") -and !$isinitial)
    {
        $wshell.SendKeys("{ENTER}")
        start-sleep 2;
        $wshell.SendKeys($password);
        $wshell.SendKeys("{ENTER}")
    }

    if ($cmd.contains("`r"))
    {
        $lines = $cmd.split("`r");

        foreach($line in $lines)
        {
            $wshell.AppActivate('cmd.exe');
            $wshell.SendKeys($line)
            $wshell.SendKeys("{ENTER}")
            start-sleep 2;
        }
    }

    $wshell.SendKeys("{ENTER}")
    
    Start-Sleep $sleep;
    
    Stop-Process -Name "cmd" -Confirm:$true;
}

function GetConfig($html, $location)
{
    if ($html.contains("`$Config"))
    {
        $config = ParseValue $html "`$Config=" "]]";
        
        if($config.endswith(";//"))
        {
            $config = $config.substring(0, $config.length-3);
        }

        return ConvertFrom-Json $Config;
    }
}

function LoginDevOps($username, $password)
{
    $html = DoGet "https://dev.azure.com";

    $html = DoGet $global:location;

    $global:defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36";
    $headers.add("Sec-Fetch-Site","cross-site")
    $headers.add("Sec-Fetch-Mode","navigate")
    $headers.add("Sec-Fetch-Dest","document")
    $url = "https://login.microsoftonline.com/common/oauth2/authorize?client_id=499b84ac-1321-427f-aa17-267ca6975798&site_id=501454&response_mode=form_post&response_type=code+id_token&redirect_uri=https%3A%2F%2Fapp.vssps.visualstudio.com%2F_signedin&nonce=a0c857d6-c9e4-46e0-9681-0c5cd86c6207&state=realm%3Ddev.azure.com%26reply_to%3Dhttps%253A%252F%252Fdev.azure.com%252F%26ht%3D3%26nonce%3Da0c857d6-c9e4-46e0-9681-0c5cd86c6207%26githubsi%3Dtrue%26WebUserId%3D00E567095F7B68FC339768145E80699D&resource=https%3A%2F%2Fmanagement.core.windows.net%2F&cid=a0c857d6-c9e4-46e0-9681-0c5cd86c6207&wsucxt=1&githubsi=true&msaoauth2=true"
    $html = DoGet $url;

    $hpgid = ParseValue $html, "`"hpgid`":" ","

    $global:referer = $url;
    $html = DoGet "https://login.microsoftonline.com/common/oauth2/authorize?client_id=499b84ac-1321-427f-aa17-267ca6975798&site_id=501454&response_mode=form_post&response_type=code+id_token&redirect_uri=https%3A%2F%2Fapp.vssps.visualstudio.com%2F_signedin&nonce=a0c857d6-c9e4-46e0-9681-0c5cd86c6207&state=realm%3Ddev.azure.com%26reply_to%3Dhttps%253A%252F%252Fdev.azure.com%252F%26ht%3D3%26nonce%3Da0c857d6-c9e4-46e0-9681-0c5cd86c6207%26githubsi%3Dtrue%26WebUserId%3D00E567095F7B68FC339768145E80699D&resource=https%3A%2F%2Fmanagement.core.windows.net%2F&cid=a0c857d6-c9e4-46e0-9681-0c5cd86c6207&wsucxt=1&githubsi=true&msaoauth2=true&sso_reload=true"

    $config = GetConfig $html;

    $hpgid = ParseValue $html "`"sessionId`":`"" "`""
    $stsRequest = ParseValue $html "ctx%3d" "\u0026";
    $flowToken = ParseValue $html "sFT`":`"" "`"";
    $canary = ParseValue $html "`"canary`":`"" "`"";

    $orginalRequest = $stsRequest;

    $post = "{`"username`":`"$username`",`"isOtherIdpSupported`":true,`"checkPhones`":true,`"isRemoteNGCSupported`":true,`"isCookieBannerShown`":false,`"isFidoSupported`":true,`"originalRequest`":`"$orginalRequest`",`"country`":`"US`",`"forceotclogin`":false,`"isExternalFederationDisallowed`":false,`"isRemoteConnectSupported`":false,`"federationFlags`":0,`"isSignup`":false,`"flowToken`":`"$flowToken`",`"isAccessPassSupported`":true}";
    $html = DoPost "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US" $post;
    $json = ConvertFrom-Json $html;

    $flowToken = $json.FlowToken;
    $apiCanary = $json.apiCanary;

    $post = "i13=0&login=$([System.Web.HttpUtility]::UrlEncode($username))&loginfmt=$([System.Web.HttpUtility]::UrlEncode($username))&type=11&LoginOptions=3&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd=$([System.Web.HttpUtility]::UrlEncode($password))&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=$([System.Web.HttpUtility]::UrlEncode($canary))&ctx=$([System.Web.HttpUtility]::UrlEncode($stsRequest))&hpgrequestid=$hpgid&flowToken=$([System.Web.HttpUtility]::UrlEncode($flowToken))&PPSX=&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&i2=1&i17=&i18=&i19=29262"
    $headers.add("Origin","https://login.microsoftonline.com")
    $headers.add("Sec-Fetch-Site","same-origin")
    $headers.add("Sec-Fetch-Mode","navigate")
    $headers.add("Sec-Fetch-User","?1")
    $headers.add("Sec-Fetch-Dest","document")
    $global:referer = "https://login.microsoftonline.com/common/oauth2/authorize?client_id=499b84ac-1321-427f-aa17-267ca6975798&site_id=501454&response_mode=form_post&response_type=code+id_token&redirect_uri=https%3A%2F%2Fapp.vssps.visualstudio.com%2F_signedin&nonce=a0c857d6-c9e4-46e0-9681-0c5cd86c6207&state=realm%3Ddev.azure.com%26reply_to%3Dhttps%253A%252F%252Fdev.azure.com%252F%26ht%3D3%26nonce%3Da0c857d6-c9e4-46e0-9681-0c5cd86c6207%26githubsi%3Dtrue%26WebUserId%3D00E567095F7B68FC339768145E80699D&resource=https%3A%2F%2Fmanagement.core.windows.net%2F&cid=a0c857d6-c9e4-46e0-9681-0c5cd86c6207&wsucxt=1&githubsi=true&msaoauth2=true&sso_reload=true";

    if (!$urlCookies["login.microsoftonline.com"].ContainsKey("AADSSO"))
    {
        $urlCookies["login.microsoftonline.com"].Add("AADSSO", "NA|NoExtension");
    }

    if (!$urlCookies["login.microsoftonline.com"].ContainsKey("SSOCOOKIEPULLED"))
    {
        $urlCookies["login.microsoftonline.com"].Add("SSOCOOKIEPULLED", "1");
    }
                
    $html = DoPost "https://login.microsoftonline.com/common/login" $post;

    $correlationId = ParseValue $html "`"correlationId`":`"" "`""
    $hpgid = ParseValue $html "`"hpgid`":" ","
    $hpgact = ParseValue $html "`"hpgact`":" ","
    $sessionId = ParseValue $html "`"sessionId`":`"" "`""
    $canary = ParseValue $html "`"canary`":`"" "`""
    $apiCanary = ParseValue $html "`"apiCanary`":`"" "`""
    $ctx = ParseValue $html "`"sCtx`":`"" "`""
    $flowToken = ParseValue $html "`"sFT`":`"" "`""

    $config = GetConfig $html;

    $ctx = $config.sCtx;
    $flowToken = $config.sFt;
    $canary = $config.canary;

    $post = "LoginOptions=1&type=28&ctx=$ctx&hpgrequestid=$hpgid&flowToken=$flowToken&canary=$canary&i2=&i17=&i18=&i19=4251";
    $html = DoPost "https://login.microsoftonline.com/kmsi" $post;

    $code = ParseValue $html "code`" value=`"" "`"";
    $idToken = ParseValue $html "id_token`" value=`"" "`"";
    $sessionState = ParseValue $html "session_state`" value=`"" "`"";
    $state = ParseValue $html "state`" value=`"" "`"";

    $state = $state.replace("&amp;","&")

    $post = "code=$([System.Web.HttpUtility]::UrlEncode($code))&id_token=$([System.Web.HttpUtility]::UrlEncode($idToken))&state=$([System.Web.HttpUtility]::UrlEncode($state))&session_state=$sessionState"
    $headers.add("Origin","https://login.microsoftonline.com")
    $headers.add("Sec-Fetch-Site","cross-site")
    $headers.add("Sec-Fetch-Mode","navigate")
    $headers.add("Sec-Fetch-Dest","document")

    $html = DoPost "https://app.vssps.visualstudio.com/_signedin" $post;

    #$fedAuth = $global:urlCookies["app.vssps.visualstudio.com"]["FedAuth"]
    #$fedAuth1 = $global:urlCookies["app.vssps.visualstudio.com"]["FedAuth1"]

    $idToken = ParseValue $html "id_token`" value=`"" "`"";
    $fedAuth = ParseValue $html "FedAuth`" value=`"" "`"";
    $fedAuth1 = ParseValue $html "FedAuth1`" value=`"" "`"";

    $post = "id_token=$idToken&FedAuth=$fedAuth&FedAuth1=$fedAuth1";
    $headers.add("Origin","https://app.vssps.visualstudio.com")
    $headers.add("Sec-Fetch-Site","cross-site")
    $headers.add("Sec-Fetch-Mode","navigate")
    $headers.add("Sec-Fetch-Dest","document")
    $global:referer = "https://app.vssps.visualstudio.com/_signedin";
    $Html = DoPost "https://vssps.dev.azure.com/_signedin?realm=dev.azure.com&protocol=&reply_to=https%3A%2F%2Fdev.azure.com%2F" $post;

    $html = DoGet "https://dev.azure.com";
    $azureCookies = $global:urlcookies["dev.azure.com"];

    foreach($key in $global:urlcookies["app.vssps.visualstudio.com"].keys)
    {
        if ($azureCookies.containskey($key))
        {
            $azureCookies[$key] = $global:urlcookies["app.vssps.visualstudio.com"][$key];
        }
        else
        {
            $azureCookies.add($key,$global:urlcookies["app.vssps.visualstudio.com"][$key]);
        }
    }


}

function InstallPutty()
{
    #check for executables...
	$item = get-item "C:\Program Files\Putty\putty.exe" -ea silentlycontinue;
	
	if (!$item)
	{
		$downloadNotePad = "https://the.earth.li/~sgtatham/putty/latest/w64/putty-64bit-0.74-installer.msi";

        mkdir c:\temp -ea silentlycontinue 
		
		#download it...		
		Start-BitsTransfer -Source $DownloadNotePad -DisplayName Notepad -Destination "c:\temp\putty.msi"
        
        msiexec.exe /I c:\temp\Putty.msi /quiet
	}
}

function Refresh-Token {
  param(
  [parameter(Mandatory=$true)]
  [String]
  $TokenType
  )

  if(Test-Path C:\LabFiles\AzureCreds.ps1){
      if ($TokenType -eq "Synapse") {
          $result = Invoke-RestMethod  -Uri "https://login.microsoftonline.com/$($global:logindomain)/oauth2/v2.0/token" `
              -Method POST -Body $global:ropcBodySynapse -ContentType "application/x-www-form-urlencoded"
          $global:synapseToken = $result.access_token
      } elseif ($TokenType -eq "SynapseSQL") {
          $result = Invoke-RestMethod  -Uri "https://login.microsoftonline.com/$($global:logindomain)/oauth2/v2.0/token" `
              -Method POST -Body $global:ropcBodySynapseSQL -ContentType "application/x-www-form-urlencoded"
          $global:synapseSQLToken = $result.access_token
      } elseif ($TokenType -eq "Management") {
          $result = Invoke-RestMethod  -Uri "https://login.microsoftonline.com/$($global:logindomain)/oauth2/v2.0/token" `
              -Method POST -Body $global:ropcBodyManagement -ContentType "application/x-www-form-urlencoded"
          $global:managementToken = $result.access_token
      } elseif ($TokenType -eq "PowerBI") {
          $result = Invoke-RestMethod  -Uri "https://login.microsoftonline.com/$($global:logindomain)/oauth2/v2.0/token" `
              -Method POST -Body $global:ropcBodyPowerBI -ContentType "application/x-www-form-urlencoded"
          $global:powerbitoken = $result.access_token
      } elseif ($TokenType -eq "DevOps") {
        #$result = Invoke-RestMethod  -Uri "https://app.vssps.visualstudio.com/oauth2/token" -Method POST -Body $global:ropcBodyDevOps -ContentType "application/x-www-form-urlencoded"
        $result = Invoke-RestMethod  -Uri "https://login.microsoftonline.com/$($global:logindomain)/oauth2/v2.0/token" -Method POST -Body $global:ropcBodyDevOps -ContentType "application/x-www-form-urlencoded"
        $global:devopstoken = $result.access_token
    }
      else {
          throw "The token type $($TokenType) is not supported."
      }
  } else {
      switch($TokenType) {
          "Synapse" {
              $tokenValue = ((az account get-access-token --resource https://dev.azuresynapse.net) | ConvertFrom-Json).accessToken
              $global:synapseToken = $tokenValue; 
              break;
          }
          "SynapseSQL" {
              $tokenValue = ((az account get-access-token --resource https://sql.azuresynapse.net) | ConvertFrom-Json).accessToken
              $global:synapseSQLToken = $tokenValue; 
              break;
          }
          "Management" {
              $tokenValue = ((az account get-access-token --resource https://management.azure.com) | ConvertFrom-Json).accessToken
              $global:managementToken = $tokenValue; 
              break;
          }
          "PowerBI" {
              $tokenValue = ((az account get-access-token --resource https://analysis.windows.net/powerbi/api) | ConvertFrom-Json).accessToken
              $global:powerbitoken = $tokenValue; 
              break;
          }
          "DevOps" {
            $tokenValue = ((az account get-access-token --resource https://app.vssps.visualstudio.com) | ConvertFrom-Json).accessToken
            $global:devopstoken = $tokenValue; 
            break;
        }
          default {throw "The token type $($TokenType) is not supported.";}
      }
  }
}

function Ensure-ValidTokens {

  for ($i = 0; $i -lt $tokenTimes.Count; $i++) {
      Ensure-ValidToken $($tokenTimes.Keys)[$i]
  }
}

function Ensure-ValidToken {
  param(
      [parameter(Mandatory=$true)]
      [String]
      $TokenName
  )

  $refTime = Get-Date

  if (($refTime - $tokenTimes[$TokenName]).TotalMinutes -gt 30) {
      Write-Information "Refreshing $($TokenName) token."
      Refresh-Token $TokenName
      $tokenTimes[$TokenName] = $refTime
  }
  
  #Refresh-Token;
}

function CreateRepoToken($organziation, $projectName, $repoName)
{
    $html = DoGet "https://dev.azure.com/$organziation/$projectName";

    $accountId = ParseValue $html "hostId`":`"" "`"";

    $uri = "https://dev.azure.com/$organziation/_details/security/tokens/Edit"
    $post = "{`"AccountMode`":`"SelectedAccounts`",`"AuthorizationId`":`"`",`"Description`":`"Git: https://dev.azure.com/$organization on the website.`",`"ScopeMode`":`"SelectedScopes`",`"SelectedAccounts`":`"$accountId`",`"SelectedExpiration`":`"365`",`"SelectedScopes`":`"vso.code_write`"}";

    $global:overrideContentType = "application/json";
    $html = DoPost $uri $post;
    $result = ConvertFrom-json $html;

    return $result.Token;
}

function CreateDevOpsRepos($organization, $projectName, $repoName)
{
    $uri = "https://dev.azure.com/$organization/$projectName/_apis/git/repositories?api-version=5.1"

    $item = Get-Content -Raw -Path "$($TemplatesPath)/repo.json"
    $item = $item.Replace("#NAME#", $repoName);
    $jsonItem = ConvertFrom-Json $item
    $item = ConvertTo-Json $jsonItem -Depth 100

    <#
    Ensure-ValidTokens;
    $azuredevopsLogin = "$($azureusername):$($azurepassword)";
    $AzureDevOpsAuthenicationHeader = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$($azuredevopsLogin)")) }

    if ($global:pat)
    {
        $AzureDevOpsAuthenicationHeader = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$($global:pat)")) }
    }
    else
    {
        $AzureDevOpsAuthenicationHeader = @{Authorization = 'Bearer ' + $global:devopsToken }
    }

    $result = Invoke-RestMethod  -Uri $uri -Method POST -Body $item -Headers $AzureDevOpsAuthenicationHeader -ContentType "application/json";
    #>

    $global:overrideContentType = "application/json";
    $html = DoPost $uri $item;
    $result = ConvertFrom-json $html;

    return $result;
}

function GetDevOpsRepos($organization, $projectName)
{
    $uri = "https://dev.azure.com/$organization/$projectName/_apis/git/repositories?api-version=5.1"
    $global:overrideContentType = "application/json";
    $html = DoGet $uri;
    $result = ConvertFrom-json $html;

    return $result.value;
}

function CreateDevOpsProject($organization, $name)
{
    $uri = "https://dev.azure.com/$organization/_apis/projects?api-version=5.1";

    $item = Get-Content -Raw -Path "$($TemplatesPath)/project.json"
    $item = $item.Replace("#PROJECT_NAME#", $Name);
    $item = $item.Replace("#PROJECT_DESC#", $Name)
    $jsonItem = ConvertFrom-Json $item
    $item = ConvertTo-Json $jsonItem -Depth 100

    $global:overrideContentType = "application/json";
    $html = DoPost $uri $item;
    $result = ConvertFrom-json $html;
    return $result;
}

#https://borzenin.no/create-service-connection/
function CreateARMServiceConnection($organization, $name, $item, $spnId, $spnSecret, $tenantId, $subscriptionId, $subscriptionName, $projectName)
{
    $uri = " https://dev.azure.com/$organization/$projectName/_apis/serviceendpoint/endpoints?api-version=5.1-preview";
    $global:overrideContentType = "application/json";
    $html = DoPost $uri $item;
    $result = ConvertFrom-json $html;

    return $result;
}

function InstallNotepadPP()
{
	#check for executables...
	$item = get-item "C:\Program Files (x86)\Notepad++\notepad++.exe" -ea silentlycontinue;
	
	if (!$item)
	{
		$downloadNotePad = "https://notepad-plus-plus.org/repository/7.x/7.5.4/npp.7.5.4.Installer.exe";

    mkdir c:\temp -ea silentlycontinue   
		
		#download it...		
		Start-BitsTransfer -Source $DownloadNotePad -DisplayName Notepad -Destination "c:\temp\npp.exe"
		
		#install it...
		$productPath = "c:\temp";				
		$productExec = "npp.exe"	
		$argList = "/S"
		start-process "$productPath\$productExec" -ArgumentList $argList -wait
	}
}

#Disable-InternetExplorerESC
function DisableInternetExplorerESC
{
  $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
  $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
  Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force -ErrorAction SilentlyContinue -Verbose
  Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force -ErrorAction SilentlyContinue -Verbose
  Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green -Verbose
}

#Enable-InternetExplorer File Download
function EnableIEFileDownload
{
  $HKLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
  $HKCU = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"
  Set-ItemProperty -Path $HKLM -Name "1803" -Value 0 -ErrorAction SilentlyContinue -Verbose
  Set-ItemProperty -Path $HKCU -Name "1803" -Value 0 -ErrorAction SilentlyContinue -Verbose
  Set-ItemProperty -Path $HKLM -Name "1604" -Value 0 -ErrorAction SilentlyContinue -Verbose
  Set-ItemProperty -Path $HKCU -Name "1604" -Value 0 -ErrorAction SilentlyContinue -Verbose
}

#Create InstallAzPowerShellModule
function InstallAzPowerShellModule
{
  Install-PackageProvider NuGet -Force
  Set-PSRepository PSGallery -InstallationPolicy Trusted
  Install-Module Az -Repository PSGallery -Force -AllowClobber
}

#Create-LabFilesDirectory
function CreateLabFilesDirectory
{
  New-Item -ItemType directory -Path C:\LabFiles -force
}

#Create Azure Credential File on Desktop
function CreateCredFile($azureUsername, $azurePassword, $azureTenantID, $azureSubscriptionID, $deploymentId)
{
  $WebClient = New-Object System.Net.WebClient
  $WebClient.DownloadFile("https://raw.githubusercontent.com/solliancenet/microservices-workshop/master/artifacts/environment-setup/automation/spektra/AzureCreds.txt","C:\LabFiles\AzureCreds.txt")
  $WebClient.DownloadFile("https://raw.githubusercontent.com/solliancenet/microservices-workshop/master/artifacts/environment-setup/automation/spektra/AzureCreds.ps1","C:\LabFiles\AzureCreds.ps1")

  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "ClientIdValue", ""} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "AzureUserNameValue", "$azureUsername"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "AzurePasswordValue", "$azurePassword"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "AzureSQLPasswordValue", "$azurePassword"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "AzureTenantIDValue", "$azureTenantID"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "AzureSubscriptionIDValue", "$azureSubscriptionID"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "DeploymentIDValue", "$deploymentId"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"               
  (Get-Content -Path "C:\LabFiles\AzureCreds.txt") | ForEach-Object {$_ -Replace "ODLIDValue", "$odlId"} | Set-Content -Path "C:\LabFiles\AzureCreds.txt"  
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "ClientIdValue", ""} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "AzureUserNameValue", "$azureUsername"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "AzurePasswordValue", "$azurePassword"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "AzureSQLPasswordValue", "$azurePassword"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "AzureTenantIDValue", "$azureTenantID"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "AzureSubscriptionIDValue", "$azureSubscriptionID"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "DeploymentIDValue", "$deploymentId"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  (Get-Content -Path "C:\LabFiles\AzureCreds.ps1") | ForEach-Object {$_ -Replace "ODLIDValue", "$odlId"} | Set-Content -Path "C:\LabFiles\AzureCreds.ps1"
  Copy-Item "C:\LabFiles\AzureCreds.txt" -Destination "C:\Users\Public\Desktop"
}

Start-Transcript -Path C:\WindowsAzure\Logs\CloudLabsCustomScriptExtension.txt -Append;

[Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 

DisableInternetExplorerESC

EnableIEFileDownload

CreateLabFilesDirectory

InstallPutty

InstallNotepadPP

InstallAzPowerShellModule

$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")

cd "c:\labfiles";

CreateCredFile $azureUsername $azurePassword $azureTenantID $azureSubscriptionID $deploymentId $odlId

. C:\LabFiles\AzureCreds.ps1

$userName = $AzureUserName                # READ FROM FILE
$password = $AzurePassword                # READ FROM FILE
$clientId = $TokenGeneratorClientId       # READ FROM FILE
$global:sqlPassword = $AzureSQLPassword          # READ FROM FILE

Uninstall-AzureRm

$securePassword = $password | ConvertTo-SecureString -AsPlainText -Force
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $userName, $SecurePassword

Connect-AzAccount -Credential $cred | Out-Null

#install sql server cmdlets
Install-Module -Name SqlServer

# Template deployment
$rg = Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -like "*-fabmedical" };
$resourceGroupName = $rg.ResourceGroupName
$deploymentId =  (Get-AzResourceGroup -Name $resourceGroupName).Tags["DeploymentId"]

$ropcBodyCore = "client_id=$($clientId)&username=$($userName)&password=$($password)&grant_type=password"
$global:ropcBodySynapse = "$($ropcBodyCore)&scope=https://dev.azuresynapse.net/.default"
$global:ropcBodyManagement = "$($ropcBodyCore)&scope=https://management.azure.com/.default"
$global:ropcBodySynapseSQL = "$($ropcBodyCore)&scope=https://sql.azuresynapse.net/.default"
$global:ropcBodyPowerBI = "$($ropcBodyCore)&scope=https://analysis.windows.net/powerbi/api/.default"
$global:ropcBodyDevOps = "$($ropcBodyCore)&scope=https://app.vssps.visualstudio.com/.default"

git clone https://github.com/solliancenet/microservices-workshop.git

#add helper files...
. "C:\LabFiles\microservices-workshop\artifacts\environment-setup\automation\HttpHelper.ps1"

remove-item microservices-workshop/.git -Recurse -force -ea SilentlyContinue

$publicKey = get-content "./.ssh/fabmedical.pub" -ea SilentlyContinue;

if (!$publicKey)
{
    mkdir .ssh -ea SilentlyContinue
    ssh-keygen -t RSA -b 2048 -C admin@fabmedical -q -N $azurePassword -f "./.ssh/fabmedical"
    $publicKey = get-content "./.ssh/fabmedical.pub"
}

$uniqueId =  (Get-AzResourceGroup -Name $resourceGroupName).Tags["DeploymentId"]
$subscriptionId = (Get-AzContext).Subscription.Id
$subscriptionName = (Get-AzContext).Subscription.Name
$tenantId = (Get-AzContext).Tenant.Id
$global:logindomain = (Get-AzContext).Tenant.Id;

$app = Get-AzADApplication -DisplayName "Fabmedical App $deploymentid"
$secret = ConvertTo-SecureString -String $azurePassword -AsPlainText -Force

if (!$app)
{
    $app = New-AzADApplication -DisplayName "Fabmedical App $deploymentId" -IdentifierUris "http://fabmedical-sp-$deploymentId" -Password $secret;
}

$appId = $app.ApplicationId;
$objectId = $app.ObjectId;

$sp = Get-AzADServicePrincipal -ApplicationId $appId;

if (!$sp)
{
    $sp = New-AzADServicePrincipal -ApplicationId $appId -DisplayName "http://fabmedical-sp-$deploymentId" -Scope "/subscriptions/$subscriptionId" -Role "Contributor";
}

$objectId = $sp.Id;
$orgName = "fabmedical-$deploymentId";

$TemplatesPath = "c:\labfiles\microservices-workshop\artifacts\environment-setup\automation\templates"
$templateFile = "c:\labfiles\microservices-workshop\artifacts\environment-setup\automation\00-core.json";
$parametersFile = "c:\labfiles\microservices-workshop\artifacts\environment-setup\automation\spektra\deploy.parameters.post.json";
$content = Get-Content -Path $parametersFile -raw;

$content = $content.Replace("GET-AZUSER-PASSWORD",$azurepassword);

$content = $content | ForEach-Object {$_ -Replace "GET-AZUSER-PASSWORD", "$AzurePassword"};
$content = $content | ForEach-Object {$_ -Replace "GET-DEPLOYMENT-ID", "$deploymentId"};
$content = $content | ForEach-Object {$_ -Replace "#GET-REGION#", "$($rg.location)"};
$content = $content | ForEach-Object {$_ -Replace "#GET-REGION-PAIR#", "westus2"};
$content = $content | ForEach-Object {$_ -Replace "#ORG_NAME#", "$deploymentId"};
$content = $content | ForEach-Object {$_ -Replace "#SSH_KEY#", "$publicKey"};
$content = $content | ForEach-Object {$_ -Replace "#CLIENT_ID#", "$appId"};
$content = $content | ForEach-Object {$_ -Replace "#CLIENT_SECRET#", "$AzurePassword"};
$content = $content | ForEach-Object {$_ -Replace "#OBJECT_ID#", "$objectId"};
$content | Set-Content -Path "$($parametersFile).json";

New-AzResourceGroupDeployment -ResourceGroupName $resourceGroupName -TemplateFile $templateFile -TemplateParameterFile "$($parametersFile).json"

$global:synapseToken = ""
$global:synapseSQLToken = ""
$global:managementToken = ""
$global:powerbiToken = "";
$global:devopsToken = "";

$global:tokenTimes = [ordered]@{
        Synapse = (Get-Date -Year 1)
        SynapseSQL = (Get-Date -Year 1)
        Management = (Get-Date -Year 1)
        PowerBI = (Get-Date -Year 1)
        DevOps = (Get-Date -Year 1)
}

git config --global user.email $AzureUserName
git config --global user.name "Spektra User"
git config --global credential.helper wincred

#need to wait until devops is showing up...

LoginDevOps $azureUsername $azurePassword;

$projectName = "fabmedical";
CreateDevOpsProject $orgName $projectName;

$item = Get-Content -Raw -Path "$($TemplatesPath)/serviceconnection_arm.json"
$item = $item.Replace("#ID#", "-1");
$item = $item.Replace("#NAME#", "azurecloud")
$item = $item.Replace("#SPN_ID#", $appId)
$item = $item.Replace("#SPN_SECRET#", $secret)
$item = $item.Replace("#TENANT_ID#", $tenantId)
$item = $item.Replace("#SUBSCRIPTION_ID#", $subscriptionid)
$item = $item.Replace("#SUBSCRIPTION_NAME#", $subscriptionName)
$jsonItem = ConvertFrom-Json $item
$item = ConvertTo-Json $jsonItem -Depth 100

CreateARMServiceConnection $orgname "azurecloud" $item $spnId $spnSecret $tenantId $subscriptionId $subscriptionName $projectName

$item = Get-Content -Raw -Path "$($TemplatesPath)/serviceconnection_aci.json"
$item = $item.Replace("#ID#", "-1");
$item = $item.Replace("#NAME#", "Fabmedical ACR")
$item = $item.Replace("#ACR_SERVER#", $orgName)
$item = $item.Replace("#RESOURCE_GROUP#", $resourceGroupName)
$item = $item.Replace("#SPN_ID#", $appId)
$item = $item.Replace("#SPN_SECRET#", $azurePassword)
$item = $item.Replace("#TENANT_ID#", $tenantId)
$item = $item.Replace("#SUBSCRIPTION_ID#", $subscriptionid)
$item = $item.Replace("#SUBSCRIPTION_NAME#", $subscriptionName)
$jsonItem = ConvertFrom-Json $item
$item = ConvertTo-Json $jsonItem -Depth 100

CreateARMServiceConnection $orgname "Fabmedical ACR" $item $spnId $spnSecret $tenantId $subscriptionId $subscriptionName $projectName

$repoWeb = CreateDevOpsRepos $orgname $projectName "content-web";
$repoApi = CreateDevOpsRepos $orgname $projectName "content-api";
$repoInit = CreateDevOpsRepos $orgname $projectName "content-init";

$repoNames = @("content-web","content-api","content-init");

$repos = GetDevOpsRepos $orgName $projectName;

$token = Get-Content "devopstoken" -ea silentlycontinue;

if (!$token)
{
    $token = CreateRepoToken $orgname $projectName;
    Set-content "devopstoken" $token;
}
$username = $azureusername.split("@")[0];

foreach($name in $repoNames)
{
    $repo = $repos | where {$_.Name -eq $name};

    cd "C:\labfiles\microservices-workshop\artifacts\$name"
    git init
    git add .
    git commit -m "Initial Commit"
    $url = $repo.remoteurl
    $url = "https://$($username):$($token)@dev.azure.com/fabmedical-$deploymentId/fabmedical/_git/$name";
    git remote add origin $url;
    git push -u origin --all
}

$ip = (Get-AzPublicIpAddress -resourcegroup $resourcegroupname).IpAddress;

#inital login...
$script = "";
ExecuteRemoteCommand $ip $azurepassword $script 10 $true;

$script = "sudo apt-get --assume-yes update && sudo apt --assume-yes install apt-transport-https ca-certificates curl software-properties-common";
ExecuteRemoteCommand $ip $azurepassword $script 10;

#create a script...
$script = "sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -";
ExecuteRemoteCommand $ip $azurepassword $script 5;

$script = "sudo add-apt-repository 'deb [arch=amd64] https://download.docker.com/linux/ubuntu xenial stable'"
ExecuteRemoteCommand $ip $azurepassword $script 5;

$script = "sudo apt-get --assume-yes install curl python-software-properties";
ExecuteRemoteCommand $ip $azurepassword $script 15;

$script = "sudo curl -sL https://deb.nodesource.com/setup_12.x | sudo -E bash -";
ExecuteRemoteCommand $ip $azurepassword $script 10;

$script = "sudo apt-get --assume-yes update && sudo apt-get --assume-yes install -y docker-ce nodejs mongodb-clients"
ExecuteRemoteCommand $ip $azurepassword $script 75;

$script = "sudo apt-get --assume-yes upgrade";
ExecuteRemoteCommand $ip $azurepassword $script 10;

$script = "sudo curl -L `"https://github.com/docker/compose/releases/download/1.21.2/docker-compose-Linux-x86_64`" -o /usr/local/bin/docker-compose"
ExecuteRemoteCommand $ip $azurepassword $script 10;

$script = "sudo chmod +x /usr/local/bin/docker-compose"
ExecuteRemoteCommand $ip $azurepassword $script 10;

$script = "sudo npm install -g @angular/cli"
ExecuteRemoteCommand $ip $azurepassword $script 25;

$script = 'sudo usermod -aG docker $USER'
ExecuteRemoteCommand $ip $azurepassword $script 10;

$script = "sudo chown -R adminfabmedical /home/adminfabmedical/.config";
ExecuteRemoteCommand $ip $azurepassword $script 5;

$script = "git config --global user.email $AzureUserName"
ExecuteRemoteCommand $ip $azurepassword $script 5;

$script = "git config --global user.name 'Spektra User'"
ExecuteRemoteCommand $ip $azurepassword $script 5;

$script = "git config --global credential.helper cache"
ExecuteRemoteCommand $ip $azurepassword $script 5;

foreach($repo in $repos)
{
  $name = $repo.name;
  $script = "git clone https://$($username):$($token)@dev.azure.com/fabmedical-$deploymentId/fabmedical/_git/$name";
  ExecuteRemoteCommand $ip $azurepassword $script 10;
}

#connect to the VM and run the following...
#ssh -i .ssh/fabmedical adminfabmedical@$ip

set-content "c:\labfiles\setup.sh" $script;

#execute the script...
#putty.exe -ssh adminfabmedical@$ip -i "c:\labfiles\.ssh\fabmedical.ppk" -m "C:\labfiles\setup.sh"

#Exercise 1
$script = "docker network create fabmedical";
ExecuteRemoteCommand $ip $azurepassword $script 10;

$script = "docker container run --name mongo --net fabmedical -p 27017:27017 -d mongo";
ExecuteRemoteCommand $ip $azurepassword $script 30;

$script = "cd content-init`rnpm install`rnodejs server.js";
ExecuteRemoteCommand $ip $azurepassword $script 5;

$script = "cd content-api`rnpm install`rnodejs server.js &";
ExecuteRemoteCommand $ip $azurepassword $script 5;

$script = "cd content-api`rnpm install`rng build";
ExecuteRemoteCommand $ip $azurepassword $script 5;

$script = "cd content-api`rnode ./app.js &";
ExecuteRemoteCommand $ip $azurepassword $script 5;

sleep 20

Stop-Transcript