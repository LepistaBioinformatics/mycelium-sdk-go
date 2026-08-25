module github.com/LepistaBioinformatics/mycelium-sdk-go/adapters/echo

go 1.25.0

require (
	github.com/LepistaBioinformatics/mycelium-sdk-go v0.1.0
	github.com/google/uuid v1.6.0
	github.com/labstack/echo/v4 v4.15.3
)

require (
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/labstack/gommon v0.5.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
)

// The root SDK module is developed in-tree. This replace is honored only when
// this adapter is the main module (local dev/test); downstream consumers ignore
// it and resolve the published root version.
replace github.com/LepistaBioinformatics/mycelium-sdk-go => ../..
