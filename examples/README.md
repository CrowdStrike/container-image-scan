# CI Pipeline Examples

## Jenkins Pipeline

### Requirements

#### Credentials

* Github

Github credentials will need to be added to Jenkins Global Credential Manager as the ID of 'github'. This should be the username and a personal access token added with all 'repo' and child object permissions. Personal access tokens can be created at https://github.com/settings/tokens.

* DockerHub

This example uses DockerHub as the image registry. DockerHub credentials will need to be added to the Jenkins Global Credential Manager with the ID of 'dockerhub'.

* Falcon API

Falcon API credentials will need to be added as two credentials in the Jenkins Global Credential Manager as Kind 'secret text' with the IDs `FALCON_CLIENT_ID` and `FALCON_CLIENT_SECRET`.

## Azure Devops Pipeline

### Requirements

#### Variable Group and Secret Variables

This pipeline implies a [variable group](https://docs.microsoft.com/en-us/azure/devops/pipelines/library/variable-groups?view=azure-devops&tabs=yaml) named `cs_falcon_vars` with the following secret variables.

`FALCON_CLIENT_SECRET` and `FALCON_CLIENT_ID`

These variables should be secret variables and Allow access to all pipelines disabled.

These variables could also be added directly to the pipeline as secret variables in a similar manner.

Replace <YOUR_IMAGE_REPO> and <YOUR_IMAGE_TAG> in the azure-pipeline.yml with your unique values.

#### Service Connection

This also uses an authenticated docker registry [service connection](https://docs.microsoft.com/en-us/azure/devops/pipelines/library/service-endpoints?view=azure-devops&tabs=yaml) on the project named 'DockerHub'
