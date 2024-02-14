# Terraform Provider Parameters Manager

This provider allows to easily export parameters and secrets into YAML files.

In order to configure it you need to set the `directory_path`:

```terraform
provider "parameters-manager" {
  directory_path = var.kubernetes_directory_path
}
```

It should point to the path with kubernetes files.

It allows to create two types of resources:
1. `parameters-manager_parameters`
2. `parameters-manager_secrets`

`parameters-manager_parameter` needs 3 keys: `env`, `app` and `parameters`, for example:

```terraform
resource "parameters-manager_parameters" "fluentbit" {
  env = var.env_name
  app = "fluentbit"

  parameters = {
    elastic_public_host = "elasticsearch.${var.root_domain}"
    cluster = var.env_name
  }
}
```

It will save all of the parameters to the `applications/clusters/{env}/charts/{app}/parameters.yaml`

`parameters-manager_secrets` also needs 3 keys: `env`, `app` and `secrets`, for example:

```tf
resource "parameters-manager_secrets" "fluentbit" {
  env = var.env_name
  app = "fluentbit"

  secrets = {
    elastic_password = var.elastic_password
  }
}
```

It will save all of the secrets in the `applications/clusters/{env}/charts/{app}/secrets` directory. Each file will be encrypted with SOPS.

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.20

## Building The Provider

```shell
go build
```
