Set-StrictMode -Version Latest 
class ResourceSetup: CommandBase
{ 
	hidden [bool] $HasSecretSetPermission = $false;
	hidden [bool] $HasSecretGetPermission = $false;
    hidden [string] $resourceGroupName = ""
	hidden [string] $resourceGroupLocation = ""
	hidden [string] $storageAccountName = ""
	hidden [string] $keyVaultName = ""
	hidden [boolean] $cleanupFlag = $true
	[SVTResourceResolver] $Resolver = $null;

	ResourceSetup(
	[string] $subscriptionId, `
	[InvocationInfo] $invocationContext, `
	[string] $ResourceGroupLocation, `
	[SVTResourceResolver] $resolver, `
	[string] $ResourceGroupName ) : Base($subscriptionId, $invocationContext)
    {
		if([string]::IsNullOrWhiteSpace($ResourceGroupName))
		{
			$this.resourceGroupName = [UserSubscriptionDataHelper]::GetUserSubscriptionRGName();
		}else
		{
		    $this.resourceGroupName = $ResourceGroupName
		}

		if([string]::IsNullOrWhiteSpace($ResourceGroupLocation))
		{
			$this.resourceGroupLocation = [UserSubscriptionDataHelper]::GetUserSubscriptionRGLocation();
		}else
		{
		    $this.resourceGroupLocation = $ResourceGroupLocation
		}

		$this.Resolver = $resolver;
		$this.Resolver.LoadAzureResources();

		$this.DoNotOpenOutputFolder = $true;
	}

	ResourceSetup(
	[string] $subscriptionId, `
	[InvocationInfo] $invocationContext, `
	[SVTResourceResolver] $resolver
	) : Base($subscriptionId, $invocationContext)
    {
		$this.resourceGroupName = [UserSubscriptionDataHelper]::GetUserSubscriptionRGName();
	    $this.resourceGroupLocation = [UserSubscriptionDataHelper]::GetUserSubscriptionRGLocation();
		$this.Resolver = $resolver;
		$this.Resolver.LoadAzureResources();
		$this.DoNotOpenOutputFolder = $true;
	}

	[MessageData[]] SetupAzSKResources([string] $ServicePrincipalName, [bool] $ResourcePassed)
    {
		[MessageData[]] $messages = @();
		try
		{	
		    #region: Check existing Resource group or create new Resource group
			$resourceGroup = Get-AzureRmResourceGroup -Name $this.resourceGroupName -ErrorAction SilentlyContinue
			if($null -eq $resourceGroup -or ($resourceGroup | Measure-Object).Count -eq 0)
			{
			    $this.PublishCustomMessage("Creating a resource group: ["+ $this.resourceGroupName +"] ")
				if([Helpers]::NewAzSKResourceGroup($this.resourceGroupName, $this.resourceGroupLocation, $this.GetCurrentModuleVersion()))
				{
					$resourceGroup = Get-AzureRmResourceGroup -Name $this.resourceGroupName -ErrorAction SilentlyContinue
				}else
				{
				  throw ([SuppressedException]::new(("Failed to create resource group."), [SuppressedExceptionType]::Generic))
				  # Exit
				}
			}
			#endregion

			#region: Check existing storage account or create new storage account
     		$existingStorage = [UserSubscriptionDataHelper]::GetUserSubscriptionStorage()
			if(($existingStorage|Measure-Object).Count -gt 0)
			{
				$this.StorageAccountName = $existingStorage.Name
			}
			else
			{
				#create new storage
				$this.storageAccountName = ("azsk" + (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmss"))
				$this.PublishCustomMessage("Creating a storage account: ["+ $this.StorageAccountName +"] ")
				$newStorage = [Helpers]::NewAzskCompliantStorage($this.storageAccountName,$this.resourceGroupName, $this.resourceGroupLocation) 
				if(!$newStorage)
				{
					throw ([SuppressedException]::new(("Failed to create storage account."), [SuppressedExceptionType]::Generic))
				}  
				else
				{
					#apply tags
					$timestamp = $(get-date).ToUniversalTime().ToString("yyyyMMdd_HHmmss")
					$this.reportStorageTags += @{
					"CreationTime"=$timestamp;
					"LastModified"=$timestamp
					}
					Set-AzureRmStorageAccount -ResourceGroupName $newStorage.ResourceGroupName -Name $newStorage.StorageAccountName -Tag $this.reportStorageTags -Force -ErrorAction SilentlyContinue
				} 
			}		
			#$this.OutputObject.StorageAccount = [UserSubscriptionDataHelper]::GetUserSubscriptionStorage() | Select-Object Name,ResourceGroupName,Sku,Tags		
			#endregion			

			#region: Check existing key vault or create new key vault 
     		$existingKeyVault = [UserSubscriptionSecretHelper]::GetUserSubscriptionKeyVault()
			if(($existingKeyVault|Measure-Object).Count -eq 1)
			{
				$this.keyVaultName = $existingKeyVault.Name
			}
			else
			{
				#create new key vault
				$this.keyVaultName = ([Constants]::KeyVaultPreName + (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmss"))
				$this.PublishCustomMessage("Creating a new key vault: ["+ $this.keyVaultName +"] ")
				$newKeyVault = [Helpers]::NewAzskCompliantKeyVault($this.keyVaultName,$this.resourceGroupName, $this.resourceGroupLocation) 
				if(!$newKeyVault)
				{
					throw ([SuppressedException]::new(("Failed to create key vault."), [SuppressedExceptionType]::Generic))
				}  
				else
				{
					$this.keyVaultName = $newKeyVault.VaultName
				} 
			}			
			#endregion					

			#region: Check Current context permissions
			$permissionObject = [UserSubscriptionSecretHelper]:: CheckCurrentContextPermissionsOnKeyVault($this.keyVaultName, $this.resourceGroupName );
			if($null -ne $permissionObject)
			{
			 $this.HasSecretSetPermission = $permissionObject.HasSetSecretsPermissions;
			 $this.HasSecretGetPermission = $permissionObject.HasGetSecretsPermissions;
			}
			#endregion

			#region: PUT secret for each resource in key vault
			if($ResourcePassed)
			{
			    if($this.HasSecretSetPermission)
				{
					$this.SetupKeyVaultSecrets()	
				}else
				{
                    $this.PublishCustomMessage("Current context does not have 'SET Secret' permission", [MessageType]::Warning)
				}			
			}
			#endregion

			#region: Assign User Provided SPN access over key vault
			if(-not [string]::IsNullOrEmpty($ServicePrincipalName))
			{
			  $this.PublishCustomMessage("Assigning SPN ["+$($ServicePrincipalName)+"] 'GET' secret access on key vault: ["+ $this.keyVaultName +"] ")
		      [UserSubscriptionSecretHelper]:: SetupKeyVaultAccessPolicy($ServicePrincipalName);
			}
			#endregion

			#region: Assign CA SPN access over key vault

			$this.GrantCASPNAccess()
		
			#endregion
	
		}
		catch
		{
			$this.PublishException($_)
		}

		return $messages;
	}	

	[MessageData[]] SetupKeyVaultSecrets()
    {
		[MessageData[]] $messages = @();
		try
		{	
		  $resources = $this.Resolver.SVTResources | Where-Object {$_.ResourceType -ne "AzSKcfg"}
		  if(($resources | Measure-Object).Count -gt 0)
		  {
			  $resources | ForEach-Object {

				$response = ""
				  $decryptedResponse = ""
				  while ([string]::IsNullOrEmpty($decryptedResponse)){                
                       $response = Read-Host "Enter PAT (personal access token) for '$($_.ResourceId)' Databricks workspace" -AsSecureString
					   $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($response)
                       $decryptedResponse = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)				
				   }
					
                   if ($decryptedResponse.Trim() -ne "n") {
                        [UserSubscriptionSecretHelper]::SetupKeyVaultSecrets($response, $_, $this.keyVaultName);
                   }
                   else {
                        $this.PublishCustomMessage("Skipped to push secret for resource '$($_.ResourceId)'.")
                    }
			  }
		  }else
		  {
		      $this.PublishCustomMessage("No resource found with specified criteria.")
		  }
		}
		catch
		{
			$this.PublishException($_)
		}

		return $messages;
	}	

	[MessageData[]] GrantCASPNAccess()
	{
	   # Move this to helper
	   [MessageData[]] $messages = @();
	   try
	   {
	     $AutomationAccountName = ([UserSubscriptionDataHelper]::GetCAName());
		 $ccAccount = [CCAutomation]::new($this.SubscriptionContext.SubscriptionId, $PSCmdlet.MyInvocation);
		 $SPN = $ccAccount.GetRunAsConnection();
		 if($null -ne $SPN -and [Helpers]::CheckMember($SPN,"FieldDefinitionValues"))
		 {
		    $this.PublishCustomMessage("Assigning CA SPN 'GET' secret access on key vault: ["+ $this.keyVaultName +"] ")
			$AppId = $SPN.FieldDefinitionValues["ApplicationId"]
			[UserSubscriptionSecretHelper]:: SetupKeyVaultAccessPolicy($AppId);
			#$AutomationAccount = Get-AzureRmResource -ResourceGroupName $this.resourceGroupName -Name $AutomationAccountName -ErrorAction silentlycontinue
		 }
	   }catch{
         # No need to break execution
	   }
	   return $messages;
	}

}



