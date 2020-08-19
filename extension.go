package proxychannel

import (
	"fmt"
	"sync"
)

// ExtensionManager manage extensions
type ExtensionManager struct {
	extensions map[string]Extension
}

// NewExtensionManager initialize an extension
func NewExtensionManager(m map[string]Extension) *ExtensionManager {
	em := &ExtensionManager{
		extensions: m,
	}
	return em
}

// GetExtension get extension by name
func (em *ExtensionManager) GetExtension(name string) (Extension, error) {
	ext, ok := em.extensions[name]
	if !ok {
		return nil, fmt.Errorf("No extension named %s", name)
	}
	return ext, nil
}

// Setup setup all extensions one by one
func (em *ExtensionManager) Setup() {
	var wg sync.WaitGroup
	for name, ext := range em.extensions {
		wg.Add(1)
		go func(name string, ext Extension) {
			defer wg.Done()
			Logger.Infof("Extension [%s] Setup start!\n", name)
			if err := ext.Setup(); err != nil {
				// if sth went wrong, delete the ext in extensions
			}
			Logger.Infof("Extension [%s] Setup done!\n", name)
		}(name, ext)
	}
	wg.Wait()
}

// Cleanup cleanup all extensions one by one, dont know if the order matters
func (em *ExtensionManager) Cleanup() {
	var wg sync.WaitGroup
	for name, ext := range em.extensions {
		wg.Add(1)
		go func(name string, ext Extension) {
			defer wg.Done()
			Logger.Infof("Extension [%s] Cleanup start!\n", name)
			if err := ext.Cleanup(); err != nil {
				Logger.Errorf("Extension [%s] Cleanup: %v\n", name, err)
				return
			}
			Logger.Infof("Extension [%s] Cleanup done!\n", name)
		}(name, ext)
	}
	wg.Wait()
}

// Extension python version __init__(self, engine, **kwargs)
type Extension interface {
	Setup() error
	Cleanup() error
	GetExtensionManager() (*ExtensionManager, error)
}
