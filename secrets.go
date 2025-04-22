package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
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
		Schema: map[string]*schema.Schema{
			"secrets": {
				Type:      schema.TypeMap,
				Required:  true,
				Elem:      &schema.Schema{Type: schema.TypeString},
				Sensitive: true,
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
		CreateContext: resourceSecretsCreate,
		ReadContext:   resourceSecretsRead,
		UpdateContext: resourceSecretsUpdate,
		DeleteContext: resourceSecretsDelete,
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

func resourceSecretsCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tflog.Debug(ctx, "Entering resourceSecretsCreate")
	var diags diag.Diagnostics

	config, ok := m.(*Config)
	if !ok {
		return diag.Errorf("Provider configuration is not valid")
	}
	directoryPath := config.DirectoryPath
	awsProfile := config.AwsProfile

	secrets, ok := d.Get("secrets").(map[string]interface{})
	if !ok {
		return diag.Errorf("Could not fetch parameter 'secrets'")
	}
	app, ok := d.Get("app").(string)
	if !ok {
		return diag.Errorf("Could not fetch parameter 'app'")
	}
	env, ok := d.Get("env").(string)
	if !ok {
		return diag.Errorf("Could not fetch parameter 'env'")
	}

	tflog.Error(ctx, fmt.Sprintf("TESTING LOG VISIBILITY: Create secrets: app=%s, env=%s, directoryPath=%s, secretCount=%d", app, env, directoryPath, len(secrets)))

	for secretName, val := range secrets {
		tflog.Debug(ctx, fmt.Sprintf("Creating secret: name=%s", secretName))
		err := createSecret(ctx, awsProfile, directoryPath, app, env, secretName, val)
		if err != nil {
			return diag.FromErr(fmt.Errorf("Couldn't create a secret %s: %w", secretName, err))
		}
	}

	id := fmt.Sprintf("%s-%s", env, app)
	d.SetId(id)
	tflog.Debug(ctx, fmt.Sprintf("Resource created with ID: %s", d.Id()))

	tflog.Debug(ctx, "Exiting resourceSecretsCreate")
	return diags
}

func createSecret(ctx context.Context, awsProfile, directoryPath string, app string, env string, secretName string, val interface{}) error {
	tflog.Debug(ctx, fmt.Sprintf("Entering createSecret: directoryPath=%s, app=%s, env=%s, secretName=%s", directoryPath, app, env, secretName))
	secretValue := map[string]interface{}{
		"value":     val,
		"managedBy": "terraform-provider-parameters-manager",
	}

	unencryptedFilePath := secretPath(directoryPath, env, app, secretName, false)
	encryptedFilePath := secretPath(directoryPath, env, app, secretName, true)
	secretsDir := secretsDir(directoryPath, env, app)
	tflog.Debug(ctx, fmt.Sprintf("Secret file paths determined: unencrypted=%s, encrypted=%s, secretsDir=%s", unencryptedFilePath, encryptedFilePath, secretsDir))

	yamlContent, err := mapToYaml(secretValue)
	if err != nil {
		return fmt.Errorf("failed to marshal secret %s to yaml: %w", secretName, err)
	}
	tflog.Debug(ctx, fmt.Sprintf("Secret marshalled to YAML: secretName=%s", secretName))

	if err := os.MkdirAll(secretsDir, 0755); err != nil {
		return fmt.Errorf("could not create secrets directory %s: %w", secretsDir, err)
	}
	tflog.Debug(ctx, fmt.Sprintf("Secrets directory ensured: path=%s", secretsDir))

	tflog.Debug(ctx, fmt.Sprintf("Writing unencrypted secret file: path=%s", unencryptedFilePath))
	if err := os.WriteFile(unencryptedFilePath, []byte(yamlContent), 0600); err != nil {
		return fmt.Errorf("could not write unencrypted secret file %s: %w", unencryptedFilePath, err)
	}

	tflog.Debug(ctx, fmt.Sprintf("Encrypting secret file using sops: source=%s, dest=%s", unencryptedFilePath, encryptedFilePath))
	if err := executeSopsEncrypt(ctx, env, awsProfile, unencryptedFilePath, encryptedFilePath); err != nil {
		return fmt.Errorf("error encrypting file for secret %s: %w", secretName, err)
	}
	tflog.Debug(ctx, fmt.Sprintf("Secret file encrypted successfully: secretName=%s", secretName))

	tflog.Debug(ctx, fmt.Sprintf("Removing unencrypted secret file: path=%s", unencryptedFilePath))
	if err := os.Remove(unencryptedFilePath); err != nil {
		tflog.Warn(ctx, fmt.Sprintf("Error removing unencrypted file, continuing operation: path=%s, error=%s", unencryptedFilePath, err.Error()))
	}

	tflog.Debug(ctx, fmt.Sprintf("Exiting createSecret: secretName=%s", secretName))
	return nil
}

func fetchExistingSecrets(ctx context.Context, awsProfile string, directoryPath string, env string, app string) (map[string]interface{}, error) {
	tflog.Debug(ctx, fmt.Sprintf("Entering fetchExistingSecrets: directoryPath=%s, env=%s, app=%s", directoryPath, env, app))
	decryptedSecrets := make(map[string]interface{})

	tflog.Debug(ctx, "Listing existing secret files")
	existingSecretFiles, err := listSecretFiles(directoryPath, env, app)
	if err != nil {
		return nil, fmt.Errorf("failed to list secret files: %w", err)
	}
	tflog.Debug(ctx, fmt.Sprintf("Found existing secret files: count=%d", len(existingSecretFiles)))

	for _, encryptedFilePath := range existingSecretFiles {
		secretName := strings.TrimSuffix(filepath.Base(encryptedFilePath), ".yaml")
		tflog.Debug(ctx, fmt.Sprintf("Processing existing secret file: path=%s, secretName=%s", encryptedFilePath, secretName))

		decryptedData, exists, err := decryptSopsFile(ctx, awsProfile, env, encryptedFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt secret file %s for %s: %w", encryptedFilePath, secretName, err)
		}

		if exists {
			val, ok := decryptedData["value"]
			if !ok {
				tflog.Warn(ctx, fmt.Sprintf("Decrypted secret file does not contain 'value' key: path=%s", encryptedFilePath))
				continue
			}
			tflog.Debug(ctx, fmt.Sprintf("Successfully decrypted secret, adding to map: secretName=%s", secretName))
			decryptedSecrets[secretName] = val
		} else {
			tflog.Warn(ctx, fmt.Sprintf("Secret file listed but reported as non-existent by decryptSopsFile: path=%s", encryptedFilePath))
		}
	}

	tflog.Debug(ctx, fmt.Sprintf("Exiting fetchExistingSecrets: secrets_found=%d", len(decryptedSecrets)))
	return decryptedSecrets, nil
}

func resourceSecretsRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tflog.Debug(ctx, "Entering resourceSecretsRead")
	var diags diag.Diagnostics

	config, ok := m.(*Config)
	if !ok {
		return diag.Errorf("Provider configuration is not valid")
	}
	directoryPath := config.DirectoryPath
	awsProfile := config.AwsProfile

	app, ok := d.Get("app").(string)
	if !ok {
		return diag.Errorf("Could not fetch parameter 'app'")
	}
	env, ok := d.Get("env").(string)
	if !ok {
		return diag.Errorf("Could not fetch parameter 'env'")
	}

	existingSecrets, err := fetchExistingSecrets(ctx, awsProfile, directoryPath, env, app)
	if err != nil {
		return diag.FromErr(fmt.Errorf("Error when fetching existing secrets: %w", err))
	}

	if err := d.Set("secrets", existingSecrets); err != nil {
		return diag.FromErr(err)
	}

	if len(existingSecrets) == 0 {
		tflog.Warn(ctx, "Secrets resource not found during read, removing from state")
		d.SetId("")
	}

	tflog.Debug(ctx, "Exiting resourceSecretsRead")
	return diags
}

func resourceSecretsUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tflog.Debug(ctx, "Entering resourceSecretsUpdate")
	var diags diag.Diagnostics

	config, ok := m.(*Config)
	if !ok {
		return diag.Errorf("Provider configuration is not valid")
	}
	directoryPath := config.DirectoryPath
	awsProfile := config.AwsProfile

	app, ok := d.Get("app").(string)
	if !ok {
		return diag.Errorf("Could not fetch parameter 'app'")
	}
	env, ok := d.Get("env").(string)
	if !ok {
		return diag.Errorf("Could not fetch parameter 'env'")
	}

	// Check if the secrets attribute has changed.
	if d.HasChange("secrets") {
		definedSecrets, ok := d.Get("secrets").(map[string]interface{})
		if !ok {
			return diag.Errorf("Could not fetch parameter 'secrets'")
		}

		existingSecrets, err := fetchExistingSecrets(ctx, awsProfile, directoryPath, env, app)
		if err != nil {
			return diag.FromErr(err)
		}

		for secretName, definedValue := range definedSecrets {
			val, ok := existingSecrets[secretName]
			if !ok || !reflect.DeepEqual(val, definedValue) {
				err := createSecret(ctx, awsProfile, directoryPath, app, env, secretName, definedValue)
				if err != nil {
					return diag.FromErr(fmt.Errorf("Couldn't update secret %s: %w", secretName, err))
				}
				existingSecrets[secretName] = definedValue
			}
		}

		for secretName := range existingSecrets {
			_, ok := definedSecrets[secretName]
			if !ok {
				tflog.Debug(ctx, fmt.Sprintf("Removing secret: name=%s, env=%s, app=%s", secretName, env, app))
				delete(existingSecrets, secretName)
				encryptedFilePath := secretPath(directoryPath, env, app, secretName, true)
				if err := os.Remove(encryptedFilePath); err != nil {
					tflog.Error(ctx, fmt.Sprintf("Error removing encrypted file: path=%s, error=%s", encryptedFilePath, err.Error()))
				} else {
					tflog.Debug(ctx, fmt.Sprintf("Successfully removed secret file: path=%s", encryptedFilePath))
				}
			}
		}

		updatedSecrets, err := fetchExistingSecrets(ctx, awsProfile, directoryPath, env, app)
		if err != nil {
			return diag.FromErr(fmt.Errorf("Failed to re-fetch secrets after update: %w", err))
		}

		if err := d.Set("secrets", updatedSecrets); err != nil {
			return diag.FromErr(err)
		}
	}

	tflog.Debug(ctx, "Exiting resourceSecretsUpdate")
	return diags
}

func listSecretFiles(directoryPath, env, app string) ([]string, error) {
	searchPattern := secretPath(directoryPath, env, app, "*", true)
	return filepath.Glob(searchPattern)
}

func decryptSopsFile(ctx context.Context, awsProfile string, env string, filePath string) (map[string]interface{}, bool, error) {
	tflog.Debug(ctx, fmt.Sprintf("Entering decryptSopsFile: filePath=%s, env=%s", filePath, env))
	if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
		tflog.Debug(ctx, fmt.Sprintf("File does not exist, returning false: filePath=%s", filePath))
		return nil, false, nil
	}

	keyCmdStr := fmt.Sprintf("aws ssm get-parameter --name /kubernetes/clusters/%s/age_key --with-decryption --query Parameter.Value --output text --profile %s --region us-east-1", env, awsProfile)
	sopsCmdStr := fmt.Sprintf("SOPS_AGE_KEY=$(%s) sops --config <(echo '') -d %s", keyCmdStr, filePath)
	cmd := exec.Command("bash", "-c", sopsCmdStr)
	tflog.Debug(ctx, fmt.Sprintf("Prepared sops decrypt command: command=%s, key_command=%s, filePath=%s", sopsCmdStr, keyCmdStr, filePath))

	var out, errb bytes.Buffer
	cmd.Stderr = &errb
	cmd.Stdout = &out

	tflog.Debug(ctx, fmt.Sprintf("Executing sops decrypt command: filePath=%s", filePath))
	err := cmd.Run()

	stdoutStr := out.String()
	stderrStr := errb.String()

	if err != nil {
		logData := map[string]interface{}{
			"command":  sopsCmdStr,
			"filePath": filePath,
			"error":    err.Error(),
			"stdout":   stdoutStr,
			"stderr":   stderrStr,
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			logData["exit_code"] = exitErr.ExitCode()
		}
		tflog.Error(ctx, fmt.Sprintf("sops decrypt command failed: command=%s, filePath=%s, error=%s", sopsCmdStr, filePath, err.Error()), logData)
		return nil, true, fmt.Errorf("sops decryption failed for %s: %w. Stderr: %s", filePath, err, stderrStr)
	}
	tflog.Debug(ctx, fmt.Sprintf("sops decrypt command succeeded: filePath=%s, stdout_preview=%s", filePath, stdoutStr))

	var secretData map[string]interface{}
	tflog.Debug(ctx, fmt.Sprintf("Unmarshalling decrypted YAML output: filePath=%s", filePath))
	if err := yaml.Unmarshal(out.Bytes(), &secretData); err != nil {
		tflog.Error(ctx, fmt.Sprintf("Failed to unmarshal decrypted sops output: filePath=%s, error=%s, stdout=%s", filePath, err.Error(), stdoutStr))
		return nil, true, fmt.Errorf("failed to parse decrypted yaml from %s: %w", filePath, err)
	}

	tflog.Debug(ctx, fmt.Sprintf("Exiting decryptSopsFile successfully: filePath=%s", filePath))
	return secretData, true, nil
}

func resourceSecretsDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	tflog.Debug(ctx, "Entering resourceSecretsDelete")
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

	secretFiles, err := listSecretFiles(directoryPath, env, app)
	if err != nil {
		return diag.FromErr(fmt.Errorf("Error listing secret files for deletion: %w", err))
	}

	tflog.Debug(ctx, fmt.Sprintf("Found secret files to delete: count=%d, env=%s, app=%s", len(secretFiles), env, app))

	for _, encryptedFilePath := range secretFiles {
		secretName := strings.TrimSuffix(filepath.Base(encryptedFilePath), ".yaml")
		tflog.Debug(ctx, fmt.Sprintf("Attempting to delete secret file: name=%s, path=%s", secretName, encryptedFilePath))

		if _, err := os.Stat(encryptedFilePath); err == nil {
			if err := os.Remove(encryptedFilePath); err != nil {
				tflog.Error(ctx, fmt.Sprintf("Error removing encrypted file during delete: path=%s, error=%s", encryptedFilePath, err.Error()))
				diags = append(diags, diag.Diagnostic{
					Severity: diag.Error,
					Summary:  fmt.Sprintf("Failed to delete secret file %s", encryptedFilePath),
					Detail:   err.Error(),
				})
			} else {
				tflog.Debug(ctx, fmt.Sprintf("Successfully deleted secret file: path=%s", encryptedFilePath))
			}
		} else if !os.IsNotExist(err) {
			tflog.Error(ctx, fmt.Sprintf("Error checking encrypted file during delete: path=%s, error=%s", encryptedFilePath, err.Error()))
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  fmt.Sprintf("Failed to check secret file %s", encryptedFilePath),
				Detail:   err.Error(),
			})
		}
	}

	d.SetId("")
	tflog.Debug(ctx, "Exiting resourceSecretsDelete")
	return diags
}

func executeSopsEncrypt(ctx context.Context, env string, awsProfile string, sourcePath string, destPath string) error {
	tflog.Debug(ctx, fmt.Sprintf("Entering executeSopsEncrypt: env=%s, sourcePath=%s, destPath=%s", env, sourcePath, destPath))
	keyCmdStr := fmt.Sprintf("aws ssm get-parameter --name /kubernetes/clusters/%s/age_public_key --with-decryption --query Parameter.Value --output text --profile %s --region us-east-1", env, awsProfile)
	sopsCmdStr := fmt.Sprintf("SOPS_AGE_RECIPIENTS=$(%s) sops --config <(echo '') -e %s > %s", keyCmdStr, sourcePath, destPath)
	cmd := exec.Command("bash", "-c", sopsCmdStr)
	tflog.Debug(ctx, fmt.Sprintf("Prepared sops encrypt command: command=%s, key_command=%s, sourcePath=%s, destPath=%s", sopsCmdStr, keyCmdStr, sourcePath, destPath))

	var errb bytes.Buffer
	cmd.Stderr = &errb

	tflog.Debug(ctx, fmt.Sprintf("Executing sops encrypt command: sourcePath=%s", sourcePath))
	err := cmd.Run()

	stderrStr := errb.String()

	if err != nil {
		logData := map[string]interface{}{
			"command":    sopsCmdStr,
			"sourcePath": sourcePath,
			"destPath":   destPath,
			"error":      err.Error(),
			"stderr":     stderrStr,
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			logData["exit_code"] = exitErr.ExitCode()
		}
		tflog.Error(ctx, fmt.Sprintf("sops encrypt command failed: command=%s, sourcePath=%s, error=%s", sopsCmdStr, sourcePath, err.Error()), logData)
		_ = os.Remove(destPath)
		return fmt.Errorf("sops encryption failed for %s: %w. Stderr: %s", sourcePath, err, stderrStr)
	}

	tflog.Debug(ctx, fmt.Sprintf("sops encrypt command succeeded: sourcePath=%s, destPath=%s", sourcePath, destPath))
	tflog.Debug(ctx, "Exiting executeSopsEncrypt successfully")
	return nil
}
