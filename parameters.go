package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"gopkg.in/yaml.v3"
)

func resourceParameters() *schema.Resource {
	return &schema.Resource{
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
		CreateContext: resourceParametersCreate,
		ReadContext:   resourceParametersRead,
		UpdateContext: resourceParametersUpdate,
		DeleteContext: resourceParametersDelete,
	}
}

func parametersPath(directoryPath string, env string, app string) string {
	return filepath.Join(directoryPath, "applications/clusters", env, "charts", app, "parameters.yaml")
}

func resourceParametersCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tflog.Debug(ctx, "Entering resourceParametersCreate")
	var diags diag.Diagnostics

	config, ok := m.(*Config) // Cast the interface{} to *Config
	if !ok {
		return diag.Errorf("Provider configuration is not valid")
	}
	directoryPath := config.DirectoryPath // Use the directory path from the provider config
	parameters, ok := d.Get("parameters").(map[string]interface{})
	if !ok {
		return diag.Errorf("Could not fetch parameter 'parameters'")
	}
	app, ok := d.Get("app").(string)
	if !ok {
		return diag.Errorf("Could not fetch parameter 'app'")
	}
	env, ok := d.Get("env").(string)
	if !ok {
		return diag.Errorf("Could not fetch parameter 'env'")
	}

	tflog.Debug(ctx, fmt.Sprintf("Creating parameters: app=%s, env=%s, directoryPath=%s, paramCount=%d", app, env, directoryPath, len(parameters)))

	yamlContent, err := mapToYaml(parameters)
	if err != nil {
		return diag.FromErr(err)
	}

	p := parametersPath(directoryPath, env, app)
	tflog.Debug(ctx, fmt.Sprintf("Writing parameters file: %s", p))

	if err := os.WriteFile(p, []byte(yamlContent), 0600); err != nil {
		return diag.FromErr(fmt.Errorf("could not write to file %s: %w", p, err))
	}

	id := fmt.Sprintf("%s-%s", env, app)
	d.SetId(id)
	tflog.Debug(ctx, fmt.Sprintf("Resource created with ID: %s", id))

	tflog.Debug(ctx, "Exiting resourceParametersCreate")
	return diags
}

func fetchExistingParameters(ctx context.Context, directoryPath string, env string, app string) (map[string]interface{}, error) {
	tflog.Debug(ctx, fmt.Sprintf("Entering fetchExistingParameters: directoryPath=%s, env=%s, app=%s", directoryPath, env, app))
	path := parametersPath(directoryPath, env, app)
	tflog.Debug(ctx, fmt.Sprintf("Checking for existing parameters file: %s", path))

	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		tflog.Debug(ctx, fmt.Sprintf("Parameters file not found, returning empty map: %s", path))
		return make(map[string]interface{}), nil
	}

	var c *map[string]interface{}
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read parameters file %s: %w", path, err)
	}

	tflog.Debug(ctx, fmt.Sprintf("Unmarshalling parameters file: %s", path))
	err = yaml.Unmarshal(yamlFile, &c)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal parameters file %s: %w", path, err)
	}

	tflog.Debug(ctx, fmt.Sprintf("Exiting fetchExistingParameters with parameter count: %d", len(*c)))
	return *c, nil
}

func resourceParametersRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tflog.Debug(ctx, "Entering resourceParametersRead")
	var diags diag.Diagnostics

	config, ok := m.(*Config) // Retrieve the provider configuration
	if !ok {
		return diag.Errorf("Provider configuration is not valid")
	}
	directoryPath := config.DirectoryPath

	app, ok := d.Get("app").(string)
	if !ok {
		return diag.Errorf("Could not fetch parameter 'app'")
	}
	env, ok := d.Get("env").(string)
	if !ok {
		return diag.Errorf("Could not fetch parameter 'env'")
	}

	tflog.Debug(ctx, fmt.Sprintf("Reading parameters: app=%s, env=%s, directoryPath=%s", app, env, directoryPath))

	parameters, err := fetchExistingParameters(ctx, directoryPath, env, app) // Pass context
	if err != nil {
		return diag.FromErr(fmt.Errorf("Error when fetching existing parameters: %w", err))
	}

	tflog.Debug(ctx, fmt.Sprintf("Setting parameters state with parameter count: %d", len(parameters)))
	if err := d.Set("parameters", parameters); err != nil {
		return diag.FromErr(err)
	}

	tflog.Debug(ctx, "Exiting resourceParametersRead")
	return diags
}

func resourceParametersUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tflog.Debug(ctx, "Entering resourceParametersUpdate")
	var diags diag.Diagnostics

	config, ok := m.(*Config)
	if !ok {
		return diag.Errorf("Provider configuration is not valid")
	}
	directoryPath := config.DirectoryPath
	definedParameters, ok := d.Get("parameters").(map[string]interface{})
	if !ok {
		return diag.Errorf("Could not fetch parameter 'parameters'")
	}
	app, ok := d.Get("app").(string)
	if !ok {
		return diag.Errorf("Could not fetch parameter 'app'")
	}
	env, ok := d.Get("env").(string)
	if !ok {
		return diag.Errorf("Could not fetch parameter 'env'")
	}

	tflog.Debug(ctx, fmt.Sprintf("Updating parameters: app=%s, env=%s, directoryPath=%s, definedParameterCount=%d", app, env, directoryPath, len(definedParameters)))

	existingParameters, err := fetchExistingParameters(ctx, directoryPath, env, app) // Pass context
	if err != nil {
		return diag.FromErr(err)
	}
	tflog.Debug(ctx, fmt.Sprintf("Fetched existing parameters with parameter count: %d", len(existingParameters)))

	needsUpdate := false
	for parameterName, definedValue := range definedParameters {
		val, ok := existingParameters[parameterName]
		if !ok || val != definedValue {
			tflog.Debug(ctx, fmt.Sprintf("Updating parameter: name=%s, newValue=%v", parameterName, definedValue))
			existingParameters[parameterName] = definedValue
			needsUpdate = true
		}
	}

	for parameterName := range existingParameters {
		_, ok := definedParameters[parameterName]
		if !ok {
			tflog.Debug(ctx, fmt.Sprintf("Removing parameter: name=%s", parameterName))
			delete(existingParameters, parameterName)
			needsUpdate = true
		}
	}

	if needsUpdate {
		tflog.Debug(ctx, "Parameters require update, writing file")
		yamlContent, err := mapToYaml(existingParameters)
		if err != nil {
			return diag.FromErr(err)
		}

		p := parametersPath(directoryPath, env, app)
		tflog.Debug(ctx, fmt.Sprintf("Writing updated parameters file: %s", p))

		if err := os.WriteFile(p, []byte(yamlContent), 0600); err != nil {
			return diag.FromErr(fmt.Errorf("could not write to file %s: %w", p, err))
		}
	} else {
		tflog.Debug(ctx, "No parameter changes detected, skipping file write")
	}

	tflog.Debug(ctx, fmt.Sprintf("Setting updated parameters state with parameter count: %d", len(existingParameters)))
	if err := d.Set("parameters", existingParameters); err != nil {
		return diag.FromErr(err)
	}

	tflog.Debug(ctx, "Exiting resourceParametersUpdate")
	return diags
}

func resourceParametersDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tflog.Debug(ctx, "Entering resourceParametersDelete")
	var diags diag.Diagnostics

	config, ok := m.(*Config)
	if !ok {
		return diag.Errorf("Provider configuration is not valid")
	}
	directoryPath := config.DirectoryPath
	app, ok := d.Get("app").(string)
	if !ok {
		return diag.Errorf("Could not fetch parameter 'app'")
	}
	env, ok := d.Get("env").(string)
	if !ok {
		return diag.Errorf("Could not fetch parameter 'env'")
	}

	tflog.Debug(ctx, fmt.Sprintf("Deleting parameters: app=%s, env=%s, directoryPath=%s", app, env, directoryPath))

	path := parametersPath(directoryPath, env, app)
	tflog.Debug(ctx, fmt.Sprintf("Checking for parameters file to delete: %s", path))

	if _, err := os.Stat(path); err == nil {
		tflog.Debug(ctx, fmt.Sprintf("Deleting parameters file: %s", path))
		if err := os.Remove(path); err != nil {
			return diag.FromErr(fmt.Errorf("error deleting parameters file %s: %w", path, err))
		}
		tflog.Debug(ctx, fmt.Sprintf("Parameters file deleted successfully: %s", path))
	} else if errors.Is(err, os.ErrNotExist) {
		tflog.Debug(ctx, fmt.Sprintf("Parameters file not found, nothing to delete: %s", path))
	} else {
		return diag.FromErr(fmt.Errorf("error checking parameters file %s: %w", path, err))
	}

	d.SetId("")
	tflog.Debug(ctx, "Exiting resourceParametersDelete")
	return diags
}
