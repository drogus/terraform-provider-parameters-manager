package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"gopkg.in/yaml.v3"
)

// mapToYaml converts a map to a YAML string.
func mapToYaml(data map[string]interface{}) (string, error) {
	out, err := yaml.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func resourceSecrets() *schema.Resource {
	return &schema.Resource{
		// Removed "directory_path" from the schema
		Schema: map[string]*schema.Schema{
			"secrets": &schema.Schema{
				Type:      schema.TypeMap,
				Required:  true,
				Elem:      &schema.Schema{Type: schema.TypeString},
				Sensitive: true,
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
		Create: resourceSecretsCreate,
		Read:   resourceSecretsRead,
		Update: resourceSecretsUpdate,
		Delete: resourceSecretsDelete,
	}
}

func secretsDir(directoryPath string, env string, app string) string {
	return filepath.Join(directoryPath, "applications/clusters", env, "charts", app, "secrets")
}

func secretPath(directoryPath string, env string, app string, secretName string, encrypted bool) string {
	var encryptedSuffix string
	if !encrypted {
		encryptedSuffix = ".unencrypted"
	}

	return filepath.Join(secretsDir(directoryPath, env, app), secretName+encryptedSuffix+".yaml")
}

func resourceSecretsCreate(d *schema.ResourceData, m interface{}) error {
	config := m.(*Config)                 // Cast the interface{} to *Config
	directoryPath := config.DirectoryPath // Use the directory path from the provider config
	awsProfile := config.AwsProfile

	secrets := d.Get("secrets").(map[string]interface{})
	app := d.Get("app").(string)
	env := d.Get("env").(string)

	for secretName, val := range secrets {
		err := createSecret(awsProfile, directoryPath, app, env, secretName, val)
		if err != nil {
			return fmt.Errorf("Couldn't create a secret %s: %s", secretName, err)
		}
	}

	id := fmt.Sprintf("%s-%s", env, app)
	d.SetId(id)

	return nil
}

func createSecret(awsProfile, directoryPath string, app string, env string, secretName string, val interface{}) error {
	secretValue := map[string]interface{}{
		"value":     val,
		"managedBy": "terraform-provider-parameters-manager",
	}

	unencryptedFilePath := secretPath(directoryPath, env, app, secretName, false)
	encryptedFilePath := secretPath(directoryPath, env, app, secretName, true)
	secretsDir := secretsDir(directoryPath, env, app)

	// Convert single secret to YAML
	yamlContent, err := mapToYaml(secretValue)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(secretsDir, 0755); err != nil {
		return fmt.Errorf("could not create a directory %s: %s", secretsDir, err)
	}

	// Write to unencrypted file
	if err := os.WriteFile(unencryptedFilePath, []byte(yamlContent), 0600); err != nil {
		return fmt.Errorf("could not write to file %s: %s", unencryptedFilePath, err)
	}

	// Encrypt file with sops
	if err := executeSopsEncrypt(env, awsProfile, unencryptedFilePath, encryptedFilePath); err != nil {
		return fmt.Errorf("error encrypting file for secret %s: %s", secretName, err)
	}

	// Delete unencrypted file
	if err := os.Remove(unencryptedFilePath); err != nil {
		return fmt.Errorf("error removing unencrypted file for secret %s: %s", secretName, err)
	}

	return nil
}

func fetchExistingSecrets(awsProfile string, directoryPath string, env string, app string) (map[string]interface{}, error) {
	// Placeholder for the decrypted secrets map
	decryptedSecrets := make(map[string]interface{})

	existingSecrets, err := listSecretFiles(directoryPath, env, app)
	if err != nil {
		return nil, err
	}

	existingSecretNames := make([]string, 0)
	for _, secretPath := range existingSecrets {
		secretName := filepath.Base(secretPath)
		secretName = strings.TrimSuffix(secretName, ".yaml")
		existingSecretNames = append(existingSecretNames, secretName)
	}

	for _, name := range existingSecretNames {
		encryptedFilePath := secretPath(directoryPath, env, app, name, true)

		// Decrypt the file with sops and read the secret value
		decryptedData, exists, err := decryptSopsFile(awsProfile, env, encryptedFilePath)
		if err != nil {
			return nil, err
		}

		if exists {
			managedBy := decryptedData["managedBy"]
			if !isNil(managedBy) {
				if managedBy == "terraform-provider-parameters-manager" {
					decryptedSecrets[name] = decryptedData["value"]
				}
			}
		}
	}

	return decryptedSecrets, nil
}

func isNil(c interface{}) bool {
	return c == nil || (reflect.ValueOf(c).Kind() == reflect.Ptr && reflect.ValueOf(c).IsNil())
}

func resourceSecretsRead(d *schema.ResourceData, m interface{}) error {
	config := m.(*Config) // Retrieve the provider configuration
	directoryPath := config.DirectoryPath
	awsProfile := config.AwsProfile

	app := d.Get("app").(string)
	env := d.Get("env").(string)

	decryptedSecrets, err := fetchExistingSecrets(awsProfile, directoryPath, env, app)
	if err != nil {
		return fmt.Errorf("Error when fetching existing secrets: %s", err)
	}

	// Update the Terraform state with the decrypted secrets
	if err := d.Set("secrets", decryptedSecrets); err != nil {
		return err
	}

	return nil
}

func resourceSecretsUpdate(d *schema.ResourceData, m interface{}) error {
	config := m.(*Config)
	directoryPath := config.DirectoryPath
	awsProfile := config.AwsProfile

	definedSecrets := d.Get("secrets").(map[string]interface{})
	app := d.Get("app").(string)
	env := d.Get("env").(string)
	ageKeysPath := filepath.Join(directoryPath, "applications/clusters", env)

	existingSecrets, err := fetchExistingSecrets(ageKeysPath, directoryPath, env, app)
	if err != nil {
		return err
	}

	for secretName, definedValue := range definedSecrets {
		val, ok := existingSecrets[secretName]
		if !ok || val != definedValue {
			// secret not in the existing map or a value differs, let's add it
			// and create the file
			existingSecrets[secretName] = definedValue
			err := createSecret(awsProfile, directoryPath, app, env, secretName, definedValue)
			if err != nil {
				return fmt.Errorf("Couldn't create a secret %s: %s", secretName, err)
			}
		}
	}

	for secretName, _ := range existingSecrets {
		_, ok := definedSecrets[secretName]
		if !ok {
			// secret is in the file, but is not defined anymore, removing
			delete(existingSecrets, secretName)
			encryptedFilePath := secretPath(directoryPath, env, app, secretName, true)
			if err := os.Remove(encryptedFilePath); err != nil {
				return fmt.Errorf("error removing encrypted file for secret %s: %s", secretName, err)
			}
		}
	}

	// Update the Terraform state with the decrypted secrets
	if err := d.Set("secrets", existingSecrets); err != nil {
		return err
	}

	return nil
}

func listSecretFiles(directoryPath, env, app string) ([]string, error) {
	searchPattern := secretPath(directoryPath, env, app, "*", true)
	return filepath.Glob(searchPattern)
}

// decryptSopsFile uses `sops` to decrypt a file and returns the decrypted secret value.
func decryptSopsFile(awsProfile string, env string, filePath string) (map[string]interface{}, bool, error) {
	if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
		// File doesn't exist, return nothing
		return nil, false, nil
	}

	// Execute sops command to decrypt the file
	key := fmt.Sprintf("SOPS_AGE_KEY=$(aws ssm get-parameter --name /kubernetes/clusters/%s/age_key --with-decryption --query Parameter.Value --output text --profile %s --region us-east-1)", env, awsProfile)
	cmd := exec.Command("bash", "-c", fmt.Sprintf("%s sops --config <(echo '') -d %s", key, filePath))

	var out, errb bytes.Buffer
	cmd.Stderr = &errb
	cmd.Stdout = &out

	// Execute the command
	err := cmd.Run()

	if err != nil {
		return nil, true, fmt.Errorf("%s", errb)
	}

	// Parse the output to extract the secret value
	// Assuming the file contains a simple "value: secret" YAML structure
	var secretData map[string]interface{}
	if err := yaml.Unmarshal(out.Bytes(), &secretData); err != nil {
		return nil, true, err
	}

	return secretData, true, nil
}

func resourceSecretsDelete(d *schema.ResourceData, m interface{}) error {
	config := m.(*Config)
	directoryPath := config.DirectoryPath
	app := d.Get("app").(string)
	env := d.Get("env").(string)
	ageKeysPath := filepath.Join(directoryPath, "applications/clusters", env)

	existingSecrets, err := fetchExistingSecrets(ageKeysPath, directoryPath, env, app)
	if err != nil {
		return err
	}

	for secretName, _ := range existingSecrets {
		encryptedFilePath := secretPath(directoryPath, env, app, secretName, true)

		// Check if the encrypted file exists
		if _, err := os.Stat(encryptedFilePath); err == nil {
			// Delete encrypted file
			if err := os.Remove(encryptedFilePath); err != nil {
				return fmt.Errorf("error removing encrypted file for secret %s: %s", secretName, err)
			}
		} else if !os.IsNotExist(err) {
			// File exists but could not be accessed for some reason
			return fmt.Errorf("error checking encrypted file for secret %s: %s", secretName, err)
		}
	}

	// After successfully deleting all files, unset the resource ID
	d.SetId("")
	return nil
}

// executeSopsEncrypt encrypts a file with sops.
func executeSopsEncrypt(env string, awsProfile string, sourcePath string, destPath string) error {
	key := fmt.Sprintf("SOPS_AGE_RECIPIENTS=$(aws ssm get-parameter --name /kubernetes/clusters/%s/age_public_key --with-decryption --query Parameter.Value --output text --profile %s --region us-east-1)", env, awsProfile)
	cmd := exec.Command("bash", "-c", fmt.Sprintf("%s sops --config <(echo '') -e %s > %s", key, sourcePath, destPath))

	var errb bytes.Buffer
	cmd.Stderr = &errb

	// Execute the command
	err := cmd.Run()

	if err != nil {
		return fmt.Errorf("%s", errb)
	}
	return nil
}
