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
        },
        ResourcesMap: map[string]*schema.Resource{
            "secrets": resourceSecrets(),
            "parameters": resourceParameters(),
        },
        ConfigureFunc: providerConfigure,
    }
}

// providerConfigure returns the configuration for the provider.
func providerConfigure(d *schema.ResourceData) (interface{}, error) {
    config := Config{
        DirectoryPath: d.Get("directory_path").(string),
    }
    return &config, nil
}

// Config struct holds provider configuration.
type Config struct {
    DirectoryPath string
}

func main() {
    plugin.Serve(&plugin.ServeOpts{
        ProviderFunc: func() *schema.Provider {
            return Provider()
        },
    })
}
