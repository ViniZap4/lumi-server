package fs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

const (
	rootDirPerm  os.FileMode = 0o700
	metaDirPerm  os.FileMode = 0o700
	noteDirPerm  os.FileMode = 0o755
	metaFilePerm os.FileMode = 0o600
	noteFilePerm os.FileMode = 0o644
)

// VaultMetadata mirrors the on-disk shape described in SPEC.md
// (`<vault>/.lumi/vault.yaml`). It uses snapshot-shaped types
// (MemberSnapshot, RoleSnapshot) rather than the canonical
// domain.Member / domain.Role to make explicit that the YAML file is a
// *cache* of authoritative server state and not a write surface for
// permissions logic.
type VaultMetadata struct {
	ID        uuid.UUID        `yaml:"id"`
	Name      string           `yaml:"name"`
	Slug      string           `yaml:"slug"`
	CreatedAt time.Time        `yaml:"created_at"`
	Server    *VaultServerLink `yaml:"server,omitempty"`
	Members   []MemberSnapshot `yaml:"members,omitempty"`
	Roles     []RoleSnapshot   `yaml:"roles,omitempty"`
}

type VaultServerLink struct {
	URL          string    `yaml:"url"`
	VaultID      uuid.UUID `yaml:"vault_id"`
	LastSyncedAt time.Time `yaml:"last_synced_at"`
}

type MemberSnapshot struct {
	Username string `yaml:"username"`
	Role     string `yaml:"role"`
}

type RoleSnapshot struct {
	Name         string   `yaml:"name"`
	Capabilities []string `yaml:"capabilities"`
	IsSeed       bool     `yaml:"is_seed,omitempty"`
}

// Manager bundles the absolute root directory under which all vaults live
// with the small set of lifecycle operations that the rest of the server
// needs. Safe for concurrent use.
type Manager struct {
	Root string
}

func NewManager(root string) (*Manager, error) {
	if root == "" {
		return nil, fmt.Errorf("storage/fs: root is required")
	}
	if !filepath.IsAbs(root) {
		abs, err := filepath.Abs(root)
		if err != nil {
			return nil, fmt.Errorf("storage/fs: cannot resolve root %q: %w", root, err)
		}
		root = abs
	}
	return &Manager{Root: filepath.Clean(root)}, nil
}

func (m *Manager) EnsureRootDir() error {
	if err := os.MkdirAll(m.Root, rootDirPerm); err != nil {
		return fmt.Errorf("storage/fs: ensure root: %w", err)
	}
	return nil
}

func (m *Manager) EnsureVaultDir(slug string) (string, error) {
	if slug == "" {
		return "", fmt.Errorf("%w: empty slug", domain.ErrValidation)
	}
	vaultDir, err := SafeJoin(m.Root, slug)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(vaultDir, noteDirPerm); err != nil {
		return "", fmt.Errorf("storage/fs: ensure vault dir: %w", err)
	}
	metaDir := filepath.Join(vaultDir, ".lumi")
	if err := os.MkdirAll(metaDir, metaDirPerm); err != nil {
		return "", fmt.Errorf("storage/fs: ensure .lumi: %w", err)
	}
	if err := os.Chmod(metaDir, metaDirPerm); err != nil {
		return "", fmt.Errorf("storage/fs: chmod .lumi: %w", err)
	}
	cacheDir := filepath.Join(metaDir, "cache")
	if err := os.MkdirAll(cacheDir, metaDirPerm); err != nil {
		return "", fmt.Errorf("storage/fs: ensure cache: %w", err)
	}
	return vaultDir, nil
}

func (m *Manager) RemoveVaultDir(slug string) error {
	if slug == "" {
		return fmt.Errorf("%w: empty slug", domain.ErrValidation)
	}
	vaultDir, err := SafeJoin(m.Root, slug)
	if err != nil {
		return err
	}
	if filepath.Clean(vaultDir) == filepath.Clean(m.Root) {
		return fmt.Errorf("%w: slug %q resolves to root", domain.ErrPathEscape, slug)
	}
	if err := os.RemoveAll(vaultDir); err != nil {
		return fmt.Errorf("storage/fs: remove vault dir: %w", err)
	}
	return nil
}

func (m *Manager) vaultYAMLPath(slug string) (string, error) {
	vaultDir, err := SafeJoin(m.Root, slug)
	if err != nil {
		return "", err
	}
	return filepath.Join(vaultDir, ".lumi", "vault.yaml"), nil
}

func (m *Manager) WriteVaultYAML(slug string, meta VaultMetadata) error {
	if _, err := m.EnsureVaultDir(slug); err != nil {
		return err
	}
	yamlPath, err := m.vaultYAMLPath(slug)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(meta)
	if err != nil {
		return fmt.Errorf("storage/fs: marshal vault.yaml: %w", err)
	}
	if err := AtomicWrite(yamlPath, data, metaFilePerm); err != nil {
		return fmt.Errorf("storage/fs: write vault.yaml: %w", err)
	}
	return nil
}

func (m *Manager) ReadVaultYAML(slug string) (VaultMetadata, error) {
	yamlPath, err := m.vaultYAMLPath(slug)
	if err != nil {
		return VaultMetadata{}, err
	}
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return VaultMetadata{}, fmt.Errorf("%w: vault.yaml for %q", domain.ErrNotFound, slug)
		}
		return VaultMetadata{}, fmt.Errorf("storage/fs: read vault.yaml: %w", err)
	}
	var meta VaultMetadata
	if err := yaml.Unmarshal(data, &meta); err != nil {
		return VaultMetadata{}, fmt.Errorf("%w: parse vault.yaml: %v", domain.ErrValidation, err)
	}
	return meta, nil
}
