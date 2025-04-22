package main

import (
	"context"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

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
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	directoryPath, ok := d.Get("directory_path").(string)
	if !ok {
		return nil, diag.Errorf("directory_path is not a string")
	}
	awsProfile, ok := d.Get("aws_profile").(string)
	if !ok {
		return nil, diag.Errorf("aws_profile is not a string")
	}

	config := &Config{
		DirectoryPath: directoryPath,
		AwsProfile:    awsProfile,
	}

	return config, nil
}

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
