Set-StrictMode -Version Latest
function Install-AzSKResources
{
	Param(

	    [string]
        [Parameter(Position = 0, Mandatory = $true,HelpMessage= "Id of the subscription in which AzSK resources needs to be installed.")]
		[ValidateNotNullOrEmpty()]
		[Alias("sid","s")]
		$SubscriptionId,
				
        [string]
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = "ResourceFilter")]
		[Alias("rgns")]
		$ResourceGroupNames,

		 [string]
        [Parameter(Mandatory = $false, ParameterSetName = "ResourceFilter")]
		[Alias("rt")]
		$ResourceType,

		[Parameter(Mandatory = $false, ParameterSetName = "ResourceFilter")]
		[ResourceTypeName]
		[Alias("rtn")]
		$ResourceTypeName = [ResourceTypeName]::All,

	    [string]
		[Parameter(Mandatory = $false, ParameterSetName = "ResourceFilter")]
		[Alias("ResourceName","rns")]
		$ResourceNames,

		[string]
		[Parameter(Mandatory = $false)]
		[Alias("spns")]
		$ServicePrincipalName,

		[Parameter(Mandatory = $false, ParameterSetName = "ResourceFilter")]
		[Alias("xrtn")]
		[ResourceTypeName]
		$ExcludeResourceTypeName = [ResourceTypeName]::All,

	    [switch]
        [Parameter(Mandatory = $false)]
		[Alias("dnof")]
		$DoNotOpenOutputFolder
    )
	Begin
	{
		[CommandHelper]::BeginCommand($PSCmdlet.MyInvocation);
		[ListenerHelper]::RegisterListeners();
	}
	Process
	{
		try 
		{
		    # Exclude resource filtering not supported here
			$resolver = [SVTResourceResolver]::new($SubscriptionId, $ResourceGroupNames, $ResourceNames, $ResourceType, $ResourceTypeName, $ExcludeResourceTypeName);			
			$resourceSetup = [ResourceSetup]::new($SubscriptionId, $PSCmdlet.MyInvocation,$resolver);

			if ($resourceSetup) 
			{
				if($PSCmdlet.ParameterSetName -eq "ResourceFilter")
				{
                  return $resourceSetup.InvokeFunction($resourceSetup.SetupAzSKResources, @($ServicePrincipalName,$true));
				}else
				{
				  return $resourceSetup.InvokeFunction($resourceSetup.SetupAzSKResources, @($ServicePrincipalName,$false));
				}	
			}
			
		}
		catch 
		{
			[EventBase]::PublishGenericException($_);
		}  
	}
	End
	{
		[ListenerHelper]::UnregisterListeners();
	}
}
