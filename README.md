# Azure

#### The following script will enumerate and disclose any concerning IAM privileges within the tenant and that is readable from the logged in account. Log in with az cli before running this tool.

RoleAssignment/Write

RoleDefinition/Write

FederatedIdentityCredentials/Write

Files will be outputted showing custom and builtin role permissions and assignments. There will also be a main summary file that will include what builtin roles by default contain these dangerous permissions.

These permissions are the ones identified and can be used for privilege escalation ;)
