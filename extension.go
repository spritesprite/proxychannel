package proxychannel

// ExtensionManager manage extensions
type ExtensionManager struct {
	extensions map[string]*Extension
	// logger     Logger
}

// NewExtensionManager initialize an extension
func NewExtensionManager(conf ExtensionManagerConfig) *ExtensionManager {
	em := &ExtensionManager{
		extensions: make(map[string]*Extension)
	}
	em.LoadExtensions(conf)
	return em
}

func (em *ExtensionManager) loadExtension(name string, econf *ExtensionConfig) {
	if extensions == nil {
		extensions = make(map[string]*Extension)
	}
	if ext, ok := extensions[name]; ok {
		// log existing extension, update
	}
	extensions[name] = econf.ExtNewFunc(em, econf.Params...)
}

// LoadExtensions load extensions from config file
func (em *ExtensionManager) LoadExtensions(conf ExtensionManagerConfig) {
	for name, econf := range conf {
		em.loadExtension(name, econf)
	}
}

// GetExtension get extension by name
func (em *ExtensionManager) GetExtension(name string) (*Extension, error) {
	if ext, ok := extensions[name]; !ok {
		return nil, errors.New("No extension named %s", name)
	}
	return ext, nil
}

// Setup setup all extensions one by one
func (em *ExtensionManager) Setup() {
	var wg sync.WaitGroup
	for name, ext := range extensions {
		wg.Add(1)
		go func(ext *Extension) {
			defer wg.Done()
			// log
			if err := ext.Setup(); err != nil {
				// if sth went wrong, delete the ext in extensions
			}
			// log
		}(ext)
	}
	wg.Wait()
}

// Cleanup cleanup all extensions one by one, dont know if the order matters
func (em *ExtensionManager) Cleanup() {
	var wg sync.WaitGroup
	for name, ext := range extensions {
		wg.Add(1)
		go func(ext *Extension) {
			defer wg.Done()
			// log
			if err := ext.Cleanup(); err != nil {
				// if sth went wrong, log
			}
			// log
		}(ext)
	}
	wg.Wait()
}

// Extension python version __init__(self, engine, **kwargs)
type Extension interface {
	Setup() error
	Cleanup() error
	GetExtensionManager() (*ExtensionManager, error)
}
