# Azure

#### The following script will enumerate and disclose any concerning IAM privileges within the tenant and that is readable from the logged in account. Log in with az cli before running this tool.

RoleAssignment/Write

RoleDefinition/Write

FederatedIdentityCredentials/Write

Files will be outputted showing custom and builtin role permissions and assignments. There will also be a main summary file that will include what builtin roles by default contain these dangerous permissions.

These permissions are the ones identified and can be used for privilege escalation ;)

====================================================================================

#### The ConReg script will verify what permissions are valid and will output the permission and scope to a file. These involve:

- Verify ability to access/enable admin keys - Can you retrieve existing admin credentials or enable the admin account for authentication
- Enumerate and test ACR task permissions - Lists existing tasks (including their managed identities) and tests if you can create new tasks with managed identities
- Enumerate and test token permissions - Lists existing repository-scoped tokens and tests if you can create new tokens for repository access


