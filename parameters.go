package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"gopkg.in/yaml.v3"
)

func resourceParameters() *schema.Resource {
	return &schema.Resource{
		// Removed "directory_path" from the schema
		Schema: map[string]*schema.Schema{
			"parameters": &schema.Schema{
				Type:     schema.TypeMap,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"app": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
			"env": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
		},
		Create: resourceParametersCreate,
		Read:   resourceParametersRead,
		Update: resourceParametersCreate, // Reuse create for updates
		Delete: resourceParametersDelete,
	}
}

func parametersFilePath(directoryPath string, env string, app string) string {
	return filepath.Join(directoryPath, "applications/clusters", env, "charts", app, "parameters.yaml")
}

func resourceParametersCreate(d *schema.ResourceData, m interface{}) error {
	config := m.(*Config)
	app := d.Get("app").(string)
	env := d.Get("env").(string)
	parameters := d.Get("parameters").(map[string]interface{})
	directoryPath := config.DirectoryPath // Use the directory path from the provider config

	parametersFilePath := parametersFilePath(directoryPath, env, app)

	yamlContent, err := mapToYaml(parameters)
	if err != nil {
		return err
	}

	if err := os.WriteFile(parametersFilePath, []byte(yamlContent), 0644); err != nil {
		return fmt.Errorf("error writing parameters file: %s", err)
	}

	// Use a combination of app and env as a unique ID for the resource
	d.SetId(fmt.Sprintf("%s-%s", env, app))
	return resourceParametersRead(d, m)
}

func resourceParametersRead(d *schema.ResourceData, m interface{}) error {
	config := m.(*Config)
	app := d.Get("app").(string)
	env := d.Get("env").(string)
	directoryPath := config.DirectoryPath // Use the directory path from the provider config

	parametersFilePath := parametersFilePath(directoryPath, env, app)

	yamlFile, err := os.ReadFile(parametersFilePath)
	if err != nil {
		return err
	}

  c := &map[string]string{}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		return err
	}

	// Update the Terraform state with the decrypted secrets
	if err := d.Set("parameters", c); err != nil {
		return err
	}

	return nil
}

func resourceParametersDelete(d *schema.ResourceData, m interface{}) error {
	directoryPath := d.Get("directory_path").(string)
	app := d.Get("app").(string)
	env := d.Get("env").(string)

	parametersFilePath := parametersFilePath(directoryPath, env, app)

	if _, err := os.Stat(parametersFilePath); err == nil {
			if err := os.Remove(parametersFilePath); err != nil {
        return fmt.Errorf("error removing parameters file %s: %s", parametersFilePath, err)
			}
		} else if !os.IsNotExist(err) {
			// File exists but could not be accessed for some reason
			return fmt.Errorf("error checking parameters file %s: %s", parametersFilePath, err)
		}

	// After successfully deleting all files, unset the resource ID
  d.SetId("")

	return nil
}
