module github.com/ismhong/ebpf_exporter

go 1.14

require (
	github.com/iovisor/gobpf v0.0.0-20200614202714-e6b321d32103
	github.com/ismhong/ebpf v0.0.0-20200814021214-6927186ae1b3
	github.com/prometheus/client_golang v1.7.1
	github.com/prometheus/common v0.11.1
	golang.org/x/sys v0.0.0-20200812155832-6a926be9bd1d
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/yaml.v2 v2.3.0
)
