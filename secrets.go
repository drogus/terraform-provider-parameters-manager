package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"gopkg.in/yaml.v3"
)

// mapToYaml converts a map to a YAML string.
func mapToYaml(data map[string]interface{}) (string, error) {
    out, err := yaml.Marshal(data)
    if err != nil {
        return "", err // Properly handle the error
    }
    return string(out), nil
}

func resourceSecrets() *schema.Resource {
    return &schema.Resource{
        // Removed "directory_path" from the schema
        Schema: map[string]*schema.Schema{
            "secrets": &schema.Schema{
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
        Create: resourceSecretsCreate,
        Read:   resourceSecretsRead,
        Update: resourceSecretsCreate, // Reuse create for updates
        Delete: resourceSecretsDelete,
    }
}

func secretPath(directoryPath string, env string, app string, secretName string, encrypted bool) string {
  return filepath.Join(directoryPath, "applications/clusters", env, "charts", app, "secrets", secretName+".unencrypted.yaml")
}

func resourceSecretsCreate(d *schema.ResourceData, m interface{}) error {
    config := m.(*Config) // Cast the interface{} to *Config
    directoryPath := config.DirectoryPath // Use the directory path from the provider config
    secrets := d.Get("secrets").(map[string]interface{})
    app := d.Get("app").(string)
    env := d.Get("env").(string)

    for key, val := range secrets {
        secretName := key // Use the map key as the file name
        secretValue := map[string]interface{}{
            "value": val,
            "managedBy": "terraform-provider-parameters-manager",
        }

        unencryptedFilePath := secretPath(directoryPath, env, app, secretName, false)
        encryptedFilePath := secretPath(directoryPath, env, app, secretName, true)

        // Convert single secret to YAML
        yamlContent, err := mapToYaml(secretValue)
        if err != nil {
            return err
        }

        // Write to unencrypted file
        if err := os.WriteFile(unencryptedFilePath, []byte(yamlContent), 0644); err != nil {
            return fmt.Errorf("error writing unencrypted file for secret %s: %s", key, err)
        }

        // Encrypt file with sops
        if err := executeSopsEncrypt(unencryptedFilePath, encryptedFilePath); err != nil {
            return fmt.Errorf("error encrypting file for secret %s: %s", key, err)
        }

        // Delete unencrypted file
        if err := os.Remove(unencryptedFilePath); err != nil {
            return fmt.Errorf("error removing unencrypted file for secret %s: %s", key, err)
        }
    }

    d.SetId(hashString(directoryPath + env + app))
    return resourceSecretsRead(d, m)
}

func hashString(s string) string {
    return fmt.Sprintf("%x", sha256.Sum256([]byte(s)))
}

func resourceSecretsRead(d *schema.ResourceData, m interface{}) error {
    config := m.(*Config) // Retrieve the provider configuration
    directoryPath := config.DirectoryPath

    // Placeholder for the decrypted secrets map
    decryptedSecrets := make(map[string]interface{})

    // Retrieve the current state of the "secrets" map
    if secrets, ok := d.GetOk("secrets"); ok {
        for key := range secrets.(map[string]interface{}) {
            encryptedFilePath := filepath.Join(directoryPath, key+".yaml")

            // Decrypt the file with sops and read the secret value
            decryptedData, err := decryptSopsFile(encryptedFilePath)
            if err != nil {
                return err
            }

            if decryptedData["managedBy"] == "terraform-provider-parameters-manager" {
              decryptedSecrets[key] = decryptedData["value"]
            }
        }
    }

    // Update the Terraform state with the decrypted secrets
    if err := d.Set("secrets", decryptedSecrets); err != nil {
        return err
    }

    return nil
}

// decryptSopsFile uses `sops` to decrypt a file and returns the decrypted secret value.
func decryptSopsFile(filePath string) (map[string]string, error) {
    // Execute sops command to decrypt the file
    cmd := exec.Command("sops", "-d", filePath)
    var out bytes.Buffer
    cmd.Stdout = &out
    err := cmd.Run()
    if err != nil {
        return nil, err
    }

    // Parse the output to extract the secret value
    // Assuming the file contains a simple "value: secret" YAML structure
    var secretData map[string]string
    if err := yaml.Unmarshal(out.Bytes(), &secretData); err != nil {
        return nil, err
    }

    return secretData, nil
}

func resourceSecretsDelete(d *schema.ResourceData, m interface{}) error {
    directoryPath := d.Get("directory_path").(string)
    secrets := d.Get("secrets").(map[string]interface{})
    app := d.Get("app").(string)
    env := d.Get("env").(string)

    // Iterate over the secrets map to delete each corresponding encrypted file
    for key := range secrets {
        secretName := key
        encryptedFilePath := secretPath(directoryPath, env, app, secretName, false)

        // Check if the encrypted file exists
        if _, err := os.Stat(encryptedFilePath); err == nil {
            // Delete encrypted file
            if err := os.Remove(encryptedFilePath); err != nil {
                return fmt.Errorf("error removing encrypted file for secret %s: %s", key, err)
            }
        } else if !os.IsNotExist(err) {
            // File exists but could not be accessed for some reason
            return fmt.Errorf("error checking encrypted file for secret %s: %s", key, err)
        }
    }

    // After successfully deleting all files, unset the resource ID
    d.SetId("")
    return nil
}

// executeSopsEncrypt encrypts a file with sops.
func executeSopsEncrypt(sourcePath, destPath string) error {
    // Construct the command
    exec.Command("sops", "-e", sourcePath, ">", destPath)
    // Since the redirection operator (>) is a shell feature, you might need to run this command through a shell interpreter like bash or sh
    cmdShell := exec.Command("bash", "-c", "sops -e "+sourcePath+" > "+destPath)

    // Execute the command
    err := cmdShell.Run()
    if err != nil {
        return err // Properly handle the error
    }
    return nil
}
