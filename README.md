# escalate-permissions GCP Cloud Function
Permission escalation works by providing the caller with a time limited membership to a role the user is normally not a member of. The cloud function must be secured to be only invokable inside the VPC. Only groups explicitly white listed have permissions to call the cloud function, this is controlled by IAM. We assume you are running in GCP for this to work.

## Permissions for function
Create a Service Account for the cloud function with the lowest possible permissions where it is allowed to allocate a role to a user e.g. Project IAM Admin

## Permissions for deployer
Create a Service Account for the cloud function deployment with the lowest possible permissions. The role `roles/cloudfunctions.admin` is required as the permission `cloudfunctions.functions.setIamPolicy` is needed.

## Permissions for callers
All callers of this function must be explicitly provided permissions. For example
`gcloud functions add-iam-policy-binding escalate-permissions --member='user:john.doe@yourorg.com' --role='roles/cloudfunctions.invoker' --region us-central1`

## Invoke function
Callers of the function must provide a valid JWT token to authenticate themselves. For example in `my-project`:

`"curl 'https://us-central1-my-project.cloudfunctions.net/escalate-permissions' --header 'Authorization: bearer $(gcloud auth print-identity-token)' -I -s"`

## Contributions

We encourage and support an active, healthy community of contributors &mdash;
including you! Details are in the [contribution guide](CONTRIBUTING.md) and
the [code of conduct](CODE_OF_CONDUCT.md). The `escalate-permissions` maintainers keep an eye on
issues and pull requests, but you can also report any negative conduct to
opensource@voiapp.io.

## License

Apache 2.0, see [LICENSE.md](LICENSE.md).
