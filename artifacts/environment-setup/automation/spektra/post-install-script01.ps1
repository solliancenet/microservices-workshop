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
        $result = Invoke-RestMethod  -Uri "https://login.microsoftonline.com/$($global:logindomain)/oauth2/v2.0/token" `
            -Method POST -Body $global:ropcBodyDevOps -ContentType "application/x-www-form-urlencoded"
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
            $tokenValue = ((az account get-access-token --resource https://dev.azure.com) | ConvertFrom-Json).accessToken
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

function CreateDevOpsRepos($organization, $name, $repoName)
{
    $uri = "https://dev.azure.com/$organization/$project/_apis/git/repositories?api-version=5.1"

    $item = Get-Content -Raw -Path "$($TemplatesPath)/repo.json"
    $item = $item.Replace("#REPO_NAME#", $repoName);
    $jsonItem = ConvertFrom-Json $item
    $item = ConvertTo-Json $jsonItem -Depth 100

    Ensure-ValidTokens;
    $result = Invoke-RestMethod  -Uri $uri -Method Post -Body $item -Headers @{ Authorization="Bearer $global:devopsToken" } -ContentType "application/json"
    return $result;
}

function GetDevOpsRepos($organization, $name)
{
    $uri = "https://dev.azure.com/$organization/$project/_apis/git/repositories?api-version=5.1"
    Ensure-ValidTokens;
    $result = Invoke-RestMethod  -Uri $uri -Method GET -Headers @{ Authorization="Bearer $global:devopsToken" } -ContentType "application/json"
    return $result;
}

function CreateDevOpsProject($organization, $name)
{
    $uri = "https://dev.azure.com/$organization/_apis/projects?api-version=5.1";

    $item = Get-Content -Raw -Path "$($TemplatesPath)/project.json"
    $item = $item.Replace("#PROJECT_NAME#", $Name);
    $item = $item.Replace("#PROJECT_DESC#", $Name)
    $jsonItem = ConvertFrom-Json $item
    $item = ConvertTo-Json $jsonItem -Depth 100

    Ensure-ValidTokens;

    $result = Invoke-RestMethod  -Uri $uri -Method POST -Body $item -Headers @{ Authorization="Bearer $global:devopsToken" } -ContentType "application/json"
}

#https://borzenin.no/create-service-connection/
function CreateARMServiceConnection($organization, $name, $template, $spnId, $spnSecret, $tenantId, $subscriptionId, $subscriptionName, $projectName)
{
    $uri = " https://dev.azure.com/$organization/$project/_apis/serviceendpoint/endpoints?api-version=5.1-preview.2";

    Ensure-ValidTokens;

    $result = Invoke-RestMethod  -Uri $uri -Method POST -Body $template -Headers @{ Authorization="Bearer $global:devopsToken" } -ContentType "application/json"
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

Start-Transcript -Path C:\WindowsAzure\Logs\CloudLabsCustomScriptExtension.txt -Append

[Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 

DisableInternetExplorerESC

EnableIEFileDownload

InstallAzPowerShellModule

InstallPutty

InstallNotepadPP

CreateLabFilesDirectory

cd "c:\labfiles";

CreateCredFile $azureUsername $azurePassword $azureTenantID $azureSubscriptionID $deploymentId $odlId

. C:\LabFiles\AzureCreds.ps1

$userName = $AzureUserName                # READ FROM FILE
$password = $AzurePassword                # READ FROM FILE
$clientId = $TokenGeneratorClientId       # READ FROM FILE
$global:sqlPassword = $AzureSQLPassword          # READ FROM FILE

$securePassword = $password | ConvertTo-SecureString -AsPlainText -Force
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $userName, $SecurePassword

Connect-AzAccount -Credential $cred | Out-Null
 
#download and install git...		
$output = "c:\LabFiles\git.exe";
Invoke-WebRequest -Uri https://github.com/git-for-windows/git/releases/download/v2.27.0.windows.1/Git-2.27.0-64-bit.exe -OutFile $output; 

$productPath = "c:\LabFiles";				
$productExec = "git.exe"	
$argList = "/SILENT"
start-process "$productPath\$productExec" -ArgumentList $argList -wait
        
#install azure cli
Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; 
Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; 
rm .\AzureCLI.msi

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
$global:ropcBodyDevOps = "$($ropcBodyCore)&scope=https://dev.azure.com/.default"

Uninstall-AzureRm

$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")

git clone https://github.com/solliancenet/microservices-workshop.git

remove-item microservices-workshop/.git -Recurse -force
mkdir .ssh
ssh-keygen -t RSA -b 2048 -C admin@fabmedical
cat .ssh/fabmedical.pub

$uniqueId =  (Get-AzResourceGroup -Name $resourceGroupName).Tags["DeploymentId"]
$subscriptionId = (Get-AzContext).Subscription.Id
$tenantId = (Get-AzContext).Tenant.Id
$global:logindomain = (Get-AzContext).Tenant.Id;

$appId = ((az ad sp create-for-rbac --role="Contributor" --scopes="/subscriptions/$subscriptionId" --name="http://Fabmedical-sp-$deploymentId") | ConvertFrom-Json).AppId;
$objectId = ((az ad sp show --id $appId --query "{objectId:@.objectId}") | ConvertFrom-Json)

$TemplatesPath = "c:\labfiles\microservices-workshop\artifacts\environment-setup\automation\templates"
$templateFile = "c:\labfiles\microservices-workshop\artifacts\environment-setup\automation\00-core.json";
$parametersFile = "c:\labfiles\microservices-workshop\artifacts\environment-setup\automation\spektra\deploy.parameters.post.json";
$content = Get-Content -Path $parametersFile;
$content = $content | ForEach-Object {$_ -Replace "GET-AZUSER-PASSWORD", "$AzurePassword"};
$content = $content | ForEach-Object {$_ -Replace "GET-DEPLOYMENT-ID", "$AzurePassword"};
$content = $content | ForEach-Object {$_ -Replace "#GET-REGION#", "$($rg.location)"};
$content = $content | ForEach-Object {$_ -Replace "#GET-REGION-PAIR#", "$($rg.location)"};
$content = $content | ForEach-Object {$_ -Replace "#ORG_NAME#", "$AzurePassword"};
$content = $content | ForEach-Object {$_ -Replace "#SSH_KEY#", "$AzurePassword"};
$content = $content | ForEach-Object {$_ -Replace "#CLIENT_ID#", "$appId"};
$content = $content | ForEach-Object {$_ -Replace "#CLIENT_SECRET#", "$AzurePassword"};
$content = $content | ForEach-Object {$_ -Replace "#OBEJCT_ID#", "$objectId"};
Set-Content -Path $parametersFile;

New-AzResourceGroupDeployment -ResourceGroupName $resourceGroupName `
  -TemplateFile $templateFile `
  -TemplateParameterFile $parametersFile

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
git config --global credential.helper cache

$projectName = "fabmedical";
CreateDevOpsProject $organization $projectName;

$item = Get-Content -Raw -Path "$($TemplatesPath)/serviceconnection_arm.json"
$item = $item.Replace("#ID#", "-1");
$item = $item.Replace("#NAME#", $name)
$item = $item.Replace("#SPN_ID#", $spnId)
$item = $item.Replace("#SPN_SECRET#", $spnSecret)
$item = $item.Replace("#TENANT_ID#", $tenantId)
$item = $item.Replace("#SUBSCRIPTION_ID#", $subscriptionid)
$item = $item.Replace("#SUBSCRIPTION_NAME#", $subscriptionName)
$jsonItem = ConvertFrom-Json $item
$item = ConvertTo-Json $jsonItem -Depth 100

CreateARMServiceConnection $organization "azurecloud" $item $spnId $spnSecret $tenantId $subscriptionId $subscriptionName $projectName

$item = Get-Content -Raw -Path "$($TemplatesPath)/serviceconnection_aci.json"
$item = $item.Replace("#ID#", "-1");
$item = $item.Replace("#NAME#", $name)
$item = $item.Replace("#SPN_ID#", $spnId)
$item = $item.Replace("#SPN_SECRET#", $spnSecret)
$item = $item.Replace("#TENANT_ID#", $tenantId)
$item = $item.Replace("#SUBSCRIPTION_ID#", $subscriptionid)
$item = $item.Replace("#SUBSCRIPTION_NAME#", $subscriptionName)
$jsonItem = ConvertFrom-Json $item
$item = ConvertTo-Json $jsonItem -Depth 100

CreateARMServiceConnection $organization "Fabmedical ACR" $item $spnId $spnSecret $tenantId $subscriptionId $subscriptionName $projectName

$repoWeb = CreateDevOpsRepo $organization $projectName "content-web";
$repoApi = CreateDevOpsRepo $organization $projectName "content-api";
$repoInit = CreateDevOpsRepo $organization $projectName "content-init";

$repos = GetDevOpsRepos $orgName $projectName;

cd content-web
git init
git add .
git commit -m "Initial Commit"
git remote add origin https://fabmedical-$deploymentId@dev.azure.com/fabmedical-$deploymentId/$ProjectName/_git/content-web
git push -u origin --all

cd ../content-api
git init
git add .
git commit -m "Initial Commit"
git remote add origin https://fabmedical-sol@dev.azure.com/fabmedical-sol/fabmedical/_git/content-api
git push -u origin --all

cd ../content-init
git init
git add .
git commit -m "Initial Commit"
git remote add origin https://fabmedical-sol@dev.azure.com/fabmedical-sol/fabmedical/_git/content-init
git push -u origin --all

$ip = ((az vm show -d -g fabmedical-$deploymentId -n fabmedical-$deploymentId --query publicIps -o tsv) | ConvertFrom-Json).PublicIps[0];

#create a script...
$break = "`r`n";
$script = "sudo apt-get update && sudo apt install apt-transport-https ca-certificates curl software-properties-common" + $break;
$script += "sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -" + $break;
$script += "sudo add-apt-repository `"deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable`"" + $break;
$script += "sudo apt-get install curl python-software-properties" + $break;
$script += "sudo curl -sL https://deb.nodesource.com/setup_12.x | sudo -E bash -" + $break;
$script += "sudo apt-get update && sudo apt-get install -y docker-ce nodejs mongodb-clients" + $break;
$script += "sudo apt-get upgrade" + $break;
$script += "sudo curl -L https://github.com/docker/compose/releases/download/1.21.2/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose" + $break;
$script += "sudo chmod +x /usr/local/bin/docker-compose" + $break;
$script += "sudo npm install -g @angular/cli" + $break;

$script += "git config --global user.email $AzureUserName" + $break;
$script += "git config --global user.name `"Spektra User`"" + $break;
$script += "git config --global credential.helper cache" + $break;

$script += "sudo chown -R `$USER:$(id -gn `$USER) /home/adminfabmedical/.config" + $break;

foreach($repon in $repos)
{
  $url = $repo.urls[0];

  #get repo url from devops...content-web/api/init
  $script += "git clone https://$($azureusername):$($azurepassword)@github.com/username/content-web.git" + $break;
  $script += "sudo chown -R `$USER:$(id -gn `$USER) /home/adminfabmedical/.config" + $break;
}

#connect to the VM and run the following...
#ssh -i .ssh/fabmedical adminfabmedical@$ip

set-content "c:\labfiles\setup.sh" $script;

#execute the script...
putty.exe -ssh adminfabmedical@$ip -pw $azurePassword -m "C:\labfiles\setup.sh"

sleep 20

Stop-Transcript