## Required Software

Ensure you have an Azure subscription you can use. If you have an MSDN subscription don't forget to activate your monthly Azure Subscription you get with that MSDN.

You will also need the following software installed

1. [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)
2. [Helm](https://helm.sh/docs/intro/install/)
3. [Kubectl](https://kubernetes.io/docs/tasks/tools/)
4. Valid TLS/SSL Certificate. One can be obtained from [LetsEncrypt](https://letsencrypt.org/) - see my previous post [here](https://darrentaylor.net/post/static-website-azure-blob-storage/)

I develop on a windows machine and use the Windows PowerShell ISE for development. I am sure there are more funkier IDEs, but this does the job for me! For ease of simplicity, I will create one large PowerShell script that can be executed line by line so you can see what is going on.

## Variables

Let’s start with declaring the variables we will use and that can be customised based on your needs.

```powershell
## Set Variables

$AZ_RESOURCE_GROUP="demo-nginx" #Your resource group
$AZ_LOCATION="northeurope" #What location you want your resources created in
$AZ_CLUSTER_NAME="demo-nginx-aks" #Name of your AKS Cluster
$AZ_VNET_NAME="demo-nginx-vnet" #Name of your VNET
$AZ_VNET_CIDR="10.222.0.0/16" #CIDR of your VNET
$AZ_AKS_CIDR="10.222.0.0/22" #CIDR of your AKS Cluster Nodes
$AZ_AKS_NAME="subnet-aks" 
$AZ_SVC_LB_CIDR="10.222.4.0/28" #CIDR of your Load Balancer
$AZ_SVC_LB_NAME="subnet-lb"
$AZ_AKS_Service_CIDR="10.223.0.0/16" #CIDR of the AKS Services
$AZ_AKS_DNS_CIDR="10.223.0.10" #IP address of the internal AKS DNS Server
$AZ_USER_ASSIGNED_IDENTITY_NAME="demo-nginx-managed-id" #Managed Identity name. Another Managed identity gets created in node pool resource group when creating the AKS cluster
$AZ_SERVICE_ACCOUNT_NAME="workload-identity-sa" # Workflow Identity service account that is created in the AKS Cluster
$AZ_SERVICE_ACCOUNT_NAMESPACE="default" #Namespace to use for your applications and service account
$AZ_FEDERATED_IDENTITY_CREDENTIAL_NAME="demo-nginx-federated-credential" #Federated identity credential name that will be linked with the workflow service account
$AZ_KeyVault_Name="demo-nginx-keyvault" #Keyvault name
$AZ_PublicIP_Name="demo-nginx-ingress-pip" #Public IP address name
$AZ_DNS_Label="demo-nginx" #DNS Label to attach to the public IP address
$AZ_IP_Address_Allow="" #Your IP address to whitelist in the network settings
$AZ_CertificateName="" #Your Certificate name for TLS termination
$AZ_CertificatePath="" #Path to your TLS certificate. The cert needs to be in pfx format.
$AZ_KeyVault_Certificates_Officer="" #Your azure account so you can add the certificate to the key vault
```

## Account and Subscription

Open up your IDE/Terminal of choice and login into Azure.

```powershell
az login
az account show
```

Then set your default account to the subscription you want to use. Make sure you have the correct permission on the subscription to create resources.

```powershell
az account set -s {Subscription Id}
```

## Create Resources

```powershell
az group create --resource-group $AZ_RESOURCE_GROUP --location $AZ_LOCATION

# Create Vnet
az network vnet create -g $AZ_RESOURCE_GROUP -n $AZ_VNET_NAME --address-prefix $AZ_VNET_CIDR

# Create Azure AKS Cluster Subnet
az network vnet subnet create --resource-group $AZ_RESOURCE_GROUP --vnet-name $AZ_VNET_NAME --name $AZ_AKS_NAME --address-prefix $AZ_AKS_CIDR

# Create the subnet for Kubernetes Service Load Balancers
az network vnet subnet create --resource-group $AZ_RESOURCE_GROUP --vnet-name $AZ_VNET_NAME --name $AZ_SVC_LB_NAME --address-prefix $AZ_SVC_LB_CIDR

#Add the service endpoints needed for all services to the AKS Subnet
az network vnet subnet update -g $AZ_RESOURCE_GROUP -n $AZ_AKS_NAME --vnet-name $AZ_VNET_NAME --service-endpoints Microsoft.KeyVault

#Create Keyvault for storing your TLS Certificate
az keyvault create -l $AZ_LOCATION -g $AZ_RESOURCE_GROUP -n $AZ_KeyVault_Name --enable-rbac-authorization --sku Standard --default-action Deny

#Get the scope to the Key Vault.
$AZ_KeyVault_Scope=$(az keyvault show --resource-group $AZ_RESOURCE_GROUP --name $AZ_KeyVault_Name --query id --output tsv)

#Get the SubnetID for use later in allowing access to the key vault
$AZ_SUBNET_ID=$(az network vnet show -g $AZ_RESOURCE_GROUP -n $AZ_VNET_NAME -o tsv --query "subnets[?name=='$AZ_AKS_NAME'].id")

#Grant access to the Keyvault that has the TLS Certificate to the AKS Subnet
az keyvault network-rule add -n $AZ_KeyVault_Name  -g $AZ_RESOURCE_GROUP  --subnet $AZ_SUBNET_ID

#Grant access to your IP Address
az keyvault network-rule add -n $AZ_KeyVault_Name -g $AZ_RESOURCE_GROUP --ip-address $AZ_IP_Address_Allow

#Grant your account access to key vault to import certificates
az role assignment create --assignee $AZ_KeyVault_Admin --role "Key Vault Administrator" --scope $AZ_KeyVault_Scope

```

You should now have your keyvault created and limited access to the VNET and your IP address. You can in the Azure portal.

Next steps are to create the AKS cluster with the azure-keyvault-secrets-provider enabled. This will allow pods on your cluster access your key vault secrets.
More information can be found [here](https://learn.microsoft.com/en-us/azure/aks/csi-secrets-store-driver)

```powershell
#Create Public IP
az network public-ip create -g $AZ_RESOURCE_GROUP -n $AZ_PublicIP_Name --allocation-method Static --sku Standard --dns-name $AZ_DNS_Label

#Get that Public IP to use later in the Ingress setup
$AZ_LB_IP=$(az network public-ip show -g $AZ_RESOURCE_GROUP -n $AZ_PublicIP_Name -o tsv --query ipAddress)

#Create Azure Kubernetes Service cluster. Note the VM size and also the azure-keyvault-secrets-provider addon for accessing the TLS certificate
az aks create --resource-group $AZ_RESOURCE_GROUP --name $AZ_CLUSTER_NAME --generate-ssh-keys --vm-set-type VirtualMachineScaleSets `
  --node-vm-size "Standard_B2s" `
  --load-balancer-sku standard `
  --enable-managed-identity `
  --enable-oidc-issuer `
  --enable-addons azure-keyvault-secrets-provider `
  --network-plugin azure `
  --network-policy azure `
  --vnet-subnet-id $AZ_SUBNET_ID `
  --node-count 3 `
  --zones 1 `
  --service-cidr $AZ_AKS_Service_CIDR `
  --dns-service-ip $AZ_AKS_DNS_CIDR `

```

To learn more about the Azure Keyvault Secrets Provider see [here](https://learn.microsoft.com/en-us/azure/aks/csi-secrets-store-driver)

Once this command completes you should have a running AKS cluster with managed identity and the azure-keyvault-secrets-provider enabled.

We will now create a managed identity - see [here](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/) for more information on managed identities.

```powershell
#Create the Managed Identity
az identity create --name $AZ_USER_ASSIGNED_IDENTITY_NAME --resource-group $AZ_RESOURCE_GROUP --location $AZ_LOCATION --subscription $AZ_SUBSCRIPTION

#Get the Client ID of the managed Identity
$AZ_USER_ASSIGNED_CLIENT_ID=$(az identity show -n $AZ_USER_ASSIGNED_IDENTITY_NAME -g $AZ_RESOURCE_GROUP --query "clientId" -otsv)

#Get the AKS OIDC_Issuer URl
$AZ_AKS_OIDC_ISSUER=$(az aks show -n $AZ_CLUSTER_NAME -g $AZ_RESOURCE_GROUP --query oidcIssuerProfile.issuerUrl -o tsv)

#Create the federated identity credential between the managed identity, service account issuer
az identity federated-credential create --name $AZ_FEDERATED_IDENTITY_CREDENTIAL_NAME --identity-name $AZ_USER_ASSIGNED_IDENTITY_NAME --resource-group $AZ_RESOURCE_GROUP --issuer $AZ_AKS_OIDC_ISSUER --subject system:serviceaccount:${AZ_SERVICE_ACCOUNT_NAMESPACE}:${AZ_SERVICE_ACCOUNT_NAME}

#Grant the managed-identity access to Key Vault  where TLS cert is stored
$AZ_KeyVault_Scope=$(az keyvault show --resource-group $AZ_RESOURCE_GROUP --name $AZ_KeyVault_Name --query id --output tsv)

az role assignment create --role "Key Vault Administrator" --assignee $AZ_USER_ASSIGNED_CLIENT_ID --scope $AZ_KeyVault_Scope 

#Need to give the managed identity the delegated permissions to the resource group the public IP address resides in
#Give the managed id reader role to the resource group
$AZ_RESOURCE_GROUP_SCOPE=$(az group show -n $AZ_RESOURCE_GROUP --query id -o tsv)
$AZ_Client_Identity=$(az aks show -n $AZ_CLUSTER_NAME -g $AZ_RESOURCE_GROUP --query identity.principalId -o tsv)

az role assignment create --assignee $AZ_Client_Identity --role "Network Contributor" --scope $AZ_RESOURCE_GROUP_SCOPE

```

We will now get the AKS Cluster credentials and add it to our local kubeconfig

```powershell

#Set the AKS Cluster
az aks get-credentials -n $AZ_CLUSTER_NAME -g $AZ_RESOURCE_GROUP
kubectl config use-context $AZ_CLUSTER_NAME

#Create ingress namespace - can be whatever you want to call it
kubectl create namespace ingress-basic

#Get the Azure Tenant ID for your subscription
$AZ_AZURE_TENANT_ID=$(az account show -s $AZ_SUBSCRIPTION --query tenantId -otsv)

```

Now we are helming so install Helm and add it to your Path environment variables. When installed and ready to use continue with the next step

```powershell

#Install the mutating webhook for the Azure Workload Identity
helm repo add azure-workload-identity https://azure.github.io/azure-workload-identity/charts
helm repo update
helm install workload-identity-webhook azure-workload-identity/workload-identity-webhook `
   --namespace azure-workload-identity-system `
   --create-namespace `
   --set azureTenantID="$AZ_AZURE_TENANT_ID"

#Create the workload identity service account in AKS
$ServiceAccountString = @"
apiVersion: v1
kind: ServiceAccount
metadata:
  annotations:
    azure.workload.identity/client-id: $AZ_USER_ASSIGNED_CLIENT_ID
  name: $AZ_SERVICE_ACCOUNT_NAME
  namespace: $AZ_SERVICE_ACCOUNT_NAMESPACE
"@

$ServiceAccountString | kubectl apply -f -

```

Now get the Client ID of the Azure Keyvault secret provider managed id. I tried using the one I created previously but that did not work. The gremlins in Azure!
And give that client ID access to the keyvault - you can reduce this permission level

```powershell

#Get the Client ID of the azurekyvaultsecrtepprovider managed id
$AZ_AKYSP_ClientId= $(az aks show -n $AZ_CLUSTER_NAME -g $AZ_RESOURCE_GROUP --query addonProfiles.azureKeyvaultSecretsProvider.identity.clientId --output tsv)

#Give that client ID the rights to Keyvault
az role assignment create --role "Key Vault Administrator" --assignee $AZ_AKYSP_ClientId --scope $AZ_KeyVault_Scope 

```

We are now going to create the Secret Provider Class. See [here](https://learn.microsoft.com/en-us/azure/aks/csi-secrets-store-driver)

```powershell

#Create the SecretProviderClass using Client ID to access your key vault

$SecretProviderClass = @"
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: azure-tls # needs to be unique per namespace
  namespace: ingress-basic
spec:
  provider: azure
  secretObjects:                            # secretObjects defines the desired state of synced K8s secret objects
  - secretName: ingress-tls-csi
    type: kubernetes.io/tls
    data: 
    - objectName: "${AZ_CertificateName}"
      key: tls.key
    - objectName: "${AZ_CertificateName}"
      key: tls.crt
  parameters:
    usePodIdentity: "false"
    useVMManagedIdentity: "true"       
    userAssignedIdentityID: "${AZ_AKYSP_ClientId}" # Setting this to use workload identity
    keyvaultName: ${AZ_KeyVault_Name}       # Set to the name of your key vault
    cloudName: ""                         # [OPTIONAL for Azure] if not provided, the Azure environment defaults to AzurePublicCloud
    objects:  |
      array:
        - |
          objectName: "${AZ_CertificateName}"
          objectType: secret              # object types: secret, key, or cert
          objectVersion: ""               # [OPTIONAL] object versions, default to latest if empty
    tenantId: "${AZ_AZURE_TENANT_ID}"
"@

$SecretProviderClass | kubectl apply -f -

```

Now installing the Nginx Controller

```powershell

#Need to have Helm installed to install the nginx ingress
# Add the ingress-nginx repository
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update

#Install Ingress
helm install ingress-nginx ingress-nginx/ingress-nginx `
    --version 4.1.3 `
    --namespace ingress-basic `
    --set controller.replicaCount=1 `
    --set controller.nodeSelector."kubernetes\.io/os"=linux `
    --set controller.image.registry=k8s.gcr.io `
    --set controller.image.image=ingress-nginx/controller `
    --set controller.image.tag=v1.2.1 `
    --set controller.image.digest="" `
    --set controller.admissionWebhooks.patch.nodeSelector."kubernetes\.io/os"=linux `
    --set controller.service.loadBalancerIP=$AZ_LB_IP `
    --set controller.service.annotations."service\.beta\.kubernetes\.io/azure-load-balancer-health-probe-request-path"=/healthz `
    --set controller.service.annotations."service\.beta\.kubernetes\.io/azure-load-balancer-resource-group"=$AZ_RESOURCE_GROUP `
    --set controller.admissionWebhooks.patch.image.registry=k8s.gcr.io `
    --set controller.admissionWebhooks.patch.image.image=ingress-nginx/kube-webhook-certgen `
    --set controller.admissionWebhooks.patch.image.tag=v1.1.1 `
    --set controller.admissionWebhooks.patch.image.digest="" `
    --set defaultBackend.nodeSelector."kubernetes\.io/os"=linux `
    --set defaultBackend.image.registry=k8s.gcr.io `
    --set defaultBackend.image.image=defaultbackend-amd64 `
    --set defaultBackend.image.tag=1.5 `
    --set defaultBackend.image.digest="" `
    --set controller.extraVolumes[0].name="secrets-store-inline" `
    --set controller.extraVolumes[0].csi.driver="secrets-store.csi.k8s.io" `
    --set controller.extraVolumes[0].csi.readOnly="true" `
    --set controller.extraVolumes[0].csi.volumeAttributes.secretProviderClass="azure-tls" `
    --set controller.extraVolumeMounts[0].name="secrets-store-inline" `
    --set controller.extraVolumeMounts[0].mountPath="/mnt/secrets-store" `
    --set controller.extraVolumeMounts[0].readOnly="true"

```

That is your AKS cluster setup so now we move onto applications to test the cluster access via HTTPS

If you have cloned this repo, you will have an Apps directory containing 2 K8S yaml files.
Update the aks-hello-world-ingress.yaml to use the correct hostname.

Make sure you are in the root directory where you cloned the repo and run the following commands

```powershell

kubectl apply -f .\Apps\aks-hello-world-deployment.yaml
kubectl apply -f .\Apps\aks-hello-world-ingress.yaml

```

Once those 2 commands have completed you should be able to browse to your https://yourdomain/hello-world-one and view the site over HTTPS.
