package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

// provider.go
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"directory_path": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The path to the directory where secrets should be saved.",
			},
			"aws_profile": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "AWS profile to use for secrets",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"parameters-manager_secrets":    resourceSecrets(),
			"parameters-manager_parameters": resourceParameters(),
		},
		ConfigureFunc: providerConfigure,
	}
}

// providerConfigure returns the configuration for the provider.
func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	config := Config{
		DirectoryPath: d.Get("directory_path").(string),
		AwsProfile:    d.Get("aws_profile").(string),
	}
	return &config, nil
}

// Config struct holds provider configuration.
type Config struct {
	DirectoryPath string
	AwsProfile    string
}

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: func() *schema.Provider {
			return Provider()
		},
	})
}
