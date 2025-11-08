package ipwhitelistshaper

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type IStorageService interface {
	Store(whitelistedIPs map[string]IPData, pendingApprovals map[string]IPData) error
	Load() (map[string]IPData, map[string]IPData, error)
}

type NoStorageService struct {}

func (n NoStorageService) Store(whitelistedIPs map[string]IPData, pendingApprovals map[string]IPData) error {
	return nil
}

func (n NoStorageService) Load() (map[string]IPData, map[string]IPData, error) {
	return nil, nil, nil
}

// StoredState represents the data that will be saved to disk
type FileStorageFormat struct {
	WhitelistedIPs   map[string]IPData `json:"whitelistedIPs"`
	PendingApprovals map[string]IPData `json:"pendingApprovals"`
}

type FileStorageService struct {
	name string
	storagePath string
}

func (s FileStorageService) Store(whitelistedIPs map[string]IPData, pendingApprovals map[string]IPData) error {
	state := FileStorageFormat{
		WhitelistedIPs:   whitelistedIPs,
		PendingApprovals: pendingApprovals,
	}

	// Log debugging info about pending approvals
	fmt.Printf("[%s] DEBUG Saving state. Pending approvals to save: %d entries\n", s.name, len(pendingApprovals))

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %v", err)
	}

	tempFile, err := os.CreateTemp(s.storagePath, "state.json.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary state file: %v", err)
	}
	tempFilename := tempFile.Name()
	err = os.WriteFile(tempFilename, data, 0644)
	if err != nil {
		os.Remove(tempFilename)
		return fmt.Errorf("failed to write temporary state file: %v", err)
	}

	stateFile := filepath.Join(s.storagePath, "state.json")
	err = os.Rename(tempFilename, stateFile)
	if err != nil {
		os.Remove(tempFilename)
		return fmt.Errorf("failed to rename temporary state file to %s: %v", stateFile, err)
	}
	return nil
}

func (f FileStorageService) Load() (map[string]IPData, map[string]IPData, error) {
    stateFile := filepath.Join(f.storagePath, "state.json")
	data, err := os.ReadFile(stateFile)
	if err != nil {
		if os.IsNotExist(err) {
			whitelistedIPs := make(map[string]IPData)
			pendingApprovals := make(map[string]IPData)
			fmt.Printf("[%s] INFO State file %s not found, initializing empty state.\n", f.name, stateFile)
			return whitelistedIPs, pendingApprovals, nil
		}
		return nil, nil, fmt.Errorf("failed to read state file %s: %v", stateFile, err)
	}

	var state FileStorageFormat
	if err = json.Unmarshal(data, &state); err != nil {
		fmt.Printf("[%s] ERROR Failed to unmarshal state from %s: %v. Starting with empty state.\n", f.name, stateFile, err)
		whitelistedIPs := make(map[string]IPData)
		pendingApprovals := make(map[string]IPData)
		return whitelistedIPs, pendingApprovals, nil
	}

	// Log debug info after loading from file
	fmt.Printf("[%s] DEBUG State loaded from file %s. Pending approvals map size: %d.\n",
		f.name, stateFile, len(state.PendingApprovals))
	return state.WhitelistedIPs, state.PendingApprovals, nil
}

type ReadOnlyStorageService struct {
	fileStorageService *FileStorageService
}

func (r ReadOnlyStorageService) Store(whitelistedIPs map[string]IPData, pendingApprovals map[string]IPData) error {
	return nil
}

func (r ReadOnlyStorageService) Load() (map[string]IPData, map[string]IPData, error) {
	return r.fileStorageService.Load()
}

func initStorageService(name string, config *Config) IStorageService {
	if config.StorageEnabled {
		if config.StoragePath != "" {
			fileStorageService := &FileStorageService{
				name: name,
				storagePath: config.StoragePath,
			}
			err := os.MkdirAll(config.StoragePath, 0755)
			if err != nil {
				// Check if directory exists but is just not writable
				if info, statErr := os.Stat(config.StoragePath); statErr == nil && info.IsDir() {
					// Directory exists but might be read-only
					fmt.Printf("[%s] WARNING: Storage directory exists but may not be writable: %v\n", name, err)
					return &ReadOnlyStorageService{ fileStorageService: fileStorageService }
				}
			} else {
				return fileStorageService
			}
		}

		// Try using a temporary directory instead
		tempDir := os.TempDir()
		tempStoragePath := filepath.Join(tempDir, "ipwhitelistshaper-"+name)
		fmt.Printf("[%s] WARNING: Cannot use configured storage path. Using temporary directory for storage: %s\n",
			name, tempStoragePath)

		// Try creating the temp directory
		if err := os.MkdirAll(tempStoragePath, 0755); err != nil {
			fmt.Printf("[%s] WARNING: Cannot create storage directory: %v. Operating in memory-only mode.\n", name, err)
		} else {
			return &FileStorageService{
				name: name,
				storagePath: tempStoragePath,
			}
		}
	}
	return &NoStorageService{}
}
