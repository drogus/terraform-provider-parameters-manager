package main

import (
	"errors"
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
			"parameters": {
				Type:     schema.TypeMap,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"app": {
				Type:     schema.TypeString,
				Required: true,
			},
			"env": {
				Type:     schema.TypeString,
				Required: true,
			},
		},
		Create: resourceParametersCreate,
		Read:   resourceParametersRead,
		Update: resourceParametersUpdate,
		Delete: resourceParametersDelete,
	}
}

func parametersPath(directoryPath string, env string, app string) string {
	return filepath.Join(directoryPath, "applications/clusters", env, "charts", app, "parameters.yaml")
}

func resourceParametersCreate(d *schema.ResourceData, m interface{}) error {
	config := m.(*Config)                 // Cast the interface{} to *Config
	directoryPath := config.DirectoryPath // Use the directory path from the provider config
	parameters := d.Get("parameters").(map[string]interface{})
	app := d.Get("app").(string)
	env := d.Get("env").(string)

	yamlContent, err := mapToYaml(parameters)
	if err != nil {
		return err
	}

	p := parametersPath(directoryPath, env, app)
	// Write to parameters.yaml file
	if err := os.WriteFile(p, []byte(yamlContent), 0600); err != nil {
		return fmt.Errorf("could not write to file %s: %s", p, err)
	}

	id := fmt.Sprintf("%s-%s", env, app)
	d.SetId(id)

	return nil
}

func fetchExistingParameters(directoryPath string, env string, app string) (map[string]interface{}, error) {
	path := parametersPath(directoryPath, env, app)

	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		// File doesn't exist, return empty map
		return make(map[string]interface{}), nil
	}

	var c *map[string]interface{}
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(yamlFile, &c)
	if err != nil {
		return nil, err
	}

	return *c, nil
}

func resourceParametersRead(d *schema.ResourceData, m interface{}) error {
	config := m.(*Config) // Retrieve the provider configuration
	directoryPath := config.DirectoryPath

	app := d.Get("app").(string)
	env := d.Get("env").(string)

	parameters, err := fetchExistingParameters(directoryPath, env, app)
	if err != nil {
		return fmt.Errorf("Error when fetching existing parameters: %s", err)
	}

	if err := d.Set("parameters", parameters); err != nil {
		return err
	}

	return nil
}

func resourceParametersUpdate(d *schema.ResourceData, m interface{}) error {
	config := m.(*Config)
	directoryPath := config.DirectoryPath
	definedParameters := d.Get("parameters").(map[string]interface{})
	app := d.Get("app").(string)
	env := d.Get("env").(string)

	existingParameters, err := fetchExistingParameters(directoryPath, env, app)
	if err != nil {
		return err
	}

	for parameterName, definedValue := range definedParameters {
		val, ok := existingParameters[parameterName]
		if !ok || val != definedValue {
			// parameter not in the existing map or a value differs, let's add it
			existingParameters[parameterName] = definedValue
		}
	}

	for parameterName := range existingParameters {
		_, ok := definedParameters[parameterName]
		if !ok {
			// parameter is in the file, but is not defined anymore, removing
			delete(existingParameters, parameterName)
		}
	}

	yamlContent, err := mapToYaml(existingParameters)
	if err != nil {
		return err
	}

	p := parametersPath(directoryPath, env, app)
	// Write to parameters.yaml file
	if err := os.WriteFile(p, []byte(yamlContent), 0600); err != nil {
		return fmt.Errorf("could not write to file %s: %s", p, err)
	}

	if err := d.Set("parameters", existingParameters); err != nil {
		return err
	}

	return nil
}

func resourceParametersDelete(d *schema.ResourceData, m interface{}) error {
	config := m.(*Config)
	directoryPath := config.DirectoryPath
	app := d.Get("app").(string)
	env := d.Get("env").(string)

	path := parametersPath(directoryPath, env, app)
	// Check if the encrypted file exists
	if _, err := os.Stat(path); err == nil {
		// Delete encrypted file
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("error parameters file %s: %s", path, err)
		}
	}

	// After successfully deleting all files, unset the resource ID
	d.SetId("")
	return nil
}
