package proxychannel

type ExtensionManager struct {
	extensions []*Extension
}

func NewExtensionManager() *ExtensionManager {

}

func (em *ExtensionManager) loadExtension() {

}

func (em *ExtensionManager) LoadExtensions() {

}

func (em *ExtensionManager) Setup(name string) {
	for name, ext := range extensions {

	}
}

func (em *ExtensionManager) Cleanup() {

}

// Extension python version __init__(self, engine, **kwargs)
type Extension interface {
	Setup()
	Cleanup()
}
