using namespace Microsoft.Azure.Management.Storage.Models
Set-StrictMode -Version Latest
class UserSubscriptionSecretHelper: AzSKRoot
{
	hidden static [string] $ResourceGroupName = [ConfigurationManager]::GetAzSKConfigData().AzSKRGName
	hidden static [string] $ResourceGroupLocation = [ConfigurationManager]::GetAzSKConfigData().AzSKLocation
	hidden static [string] $AutomationAccountName = [Constants]::AutomationAccountName
	hidden static [string] $KeyVaultResourceType = "Microsoft.KeyVault/vaults";


	UserSubscriptionSecretHelper([string] $subscriptionId):
		Base($subscriptionId)
	{
	}

	static [PSObject] CheckCurrentContextPermissionsOnKeyVault([string] $KeyVaultName ,[string] $RgName)
	{
	    $KeyVault = Get-AzureRmKeyVault -VaultName $KeyVaultName `
                                            -ResourceGroupName $RgName
	    # create Custom Object
		$CurrentContextPermissions = New-Object PSObject
        Add-Member -InputObject $CurrentContextPermissions -MemberType NoteProperty -Name HasSetSecretsPermissions -Value $false
		Add-Member -InputObject $CurrentContextPermissions -MemberType NoteProperty -Name HasGetSecretsPermissions -Value $false
		$currentContext=[Helpers]::GetCurrentRMContext();
		$CurrentContextId=$currentContext.Account.Id;
		$CurrentContextObjectId=$null
		try{
				if($currentContext.Account.Type -eq 'User')
				{
					$CurrentContextObjectId=Get-AzureRmADUser -UserPrincipalName $CurrentContextId|Select-Object -Property Id
				}
				elseif($currentContext.Account.Type -eq 'ServicePrincipal')
				{
					$CurrentContextObjectId=Get-AzureRmADServicePrincipal -ServicePrincipalName $CurrentContextId|Select-Object -Property Id
				}
				$accessPolicies = $KeyVault.AccessPolicies
				$currentContextAccess=$accessPolicies|Where-Object{$_.ObjectId -eq $CurrentContextObjectId.Id }
			
				if($null -ne $currentContextAccess)
				{
					if(('Set' -in $currentContextAccess.PermissionsToSecrets))
					{
						$CurrentContextPermissions.HasSetSecretsPermissions = $true
					}
					if(('Get' -in $currentContextAccess.PermissionsToSecrets))
					{
						$CurrentContextPermissions.HasGetSecretsPermissions = $true
					}
				}
			}
			catch
			{
				$CurrentContextPermissions.HasSetSecretsPermissions = $false;
				$CurrentContextPermissions.HasGetSecretsPermissions = $false;
			}

	 return $CurrentContextPermissions;		
	}

	static [PSObject] GetUserSubscriptionKeyVault()
	{
		$KeyVaultName = [Constants]::KeyVaultPreName
		$keyVault = Get-AzureRmResource -ResourceGroupName $([UserSubscriptionDataHelper]::ResourceGroupName) `
		-Name "*$KeyVaultName*" `
		-ResourceType $([UserSubscriptionDataHelper]::KeyVaultResourceType) `
		-ErrorAction Stop
		$keyVault = $keyVault | Where-Object{$_.Name -match '^azsk-kv\d{14}$'}

		if(($keyVault|Measure-Object).Count -gt 1)
		{
			throw [SuppressedException]::new("Multiple key vaults found in resource group: [$([UserSubscriptionDataHelper]::ResourceGroupName)]. This is not expected. Please contact support team.");
		}
		return $keyVault
	}

	static [string] SetupKeyVaultAccessPolicy([string] $SPN)
    {
	    $keyvault = [UserSubscriptionSecretHelper]:: GetUserSubscriptionKeyVault();
		if($null -ne $keyvault)
		{
			try
			{	
			   Set-AzureRmKeyVaultAccessPolicy -VaultName $keyvault.Name -ServicePrincipalName $SPN -PermissionsToSecrets Get
			}
			catch
			{
			  throw ([SuppressedException]::new(("message here , in case access policy setup fail."), [SuppressedExceptionType]::Generic))
			}
		}else
		{
		  ## Show error when unble to access key vault
		}
		return $null;
	}	

	static [string] SanitizeSecretName([string] $RawString)
	{
		$pattern = '[^a-zA-Z0-9]'
        $RawString -replace $pattern, '' 
		return $RawString;
	}

	static [string] ReadSecretFromKeyVault([string] $ResourceId)
	{
	  $keyVault = [UserSubscriptionSecretHelper]::GetUserSubscriptionKeyVault()
	  $secretValue = ""
	  try
	  {
		  if($null -ne $keyVault)
		  {
		    #
		    $SecretName  =  [Helpers]::ComputeHash($ResourceId.ToLower());
		    $Secret = Get-AzureKeyVaultSecret -VaultName $keyVault.Name -Name $SecretName
			$secretValue = $Secret.SecretValueText;
		  }else
		  {
		   # Unable to find key vault
		  }
	  }catch{
	      # Not able to fetch secret from key vault
	  } 
	  return $secretValue;
	}

	static [bool] SetupKeyVaultSecrets([securestring] $PAT,[PSObject] $Resource, [string] $KeyVaultName)
    {
		try
		{
		  $SecretName  =  [Helpers]::ComputeHash($Resource.ResourceId.ToLower());
		  $secret = Set-AzureKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName -SecretValue $PAT  -Tags @{"ResourceId" = $Resource.ResourceId} # add tags and expiry date
		  return $true;
		}
		catch
		{
		    return  $false;
			#throw ([SuppressedException]::new(("message here , in case secre set fails."), [SuppressedExceptionType]::Generic))
		}
	}
}
