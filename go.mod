module github.com/docker/cli

go 1.15

replace (
	github.com/containerd/containerd v1.4.0-0 => github.com/containerd/containerd v1.4.1
	github.com/docker/docker => ../docker
	github.com/docker/libkv => ../libkv
	github.com/docker/libnetwork => ../libnetwork
	github.com/hashicorp/go-immutable-radix => github.com/tonistiigi/go-immutable-radix v0.0.0-20170803185627-826af9ccf0fe
	github.com/jaguilar/vt100 => github.com/tonistiigi/vt100 v0.0.0-20190402012908-ad4c4a574305
	github.com/moby/buildkit => github.com/moby/buildkit v0.7.1-0.20200718032743-4d1f260e8490

)

require (
	github.com/Microsoft/hcsshim/test v0.0.0-20201030212021-6e6b6ce98037 // indirect
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412 // indirect
	github.com/bitly/go-hostpool v0.1.0 // indirect
	github.com/bugsnag/bugsnag-go v1.5.4 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cloudflare/cfssl v1.5.0 // indirect
	github.com/containerd/console v1.0.0
	github.com/containerd/containerd v1.4.1
	github.com/cpuguy83/go-md2man/v2 v2.0.0
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/docker v20.10.0-beta1.0.20201020191947-73dc6a680cdd+incompatible
	github.com/docker/docker-credential-helpers v0.6.3
	github.com/docker/go v1.5.1-1.0.20160303222718-d30aec9fd63c // indirect
	github.com/docker/go-connections v0.4.0
	github.com/docker/go-units v0.4.0
	github.com/fvbommel/sortorder v1.0.2
	github.com/gofrs/flock v0.7.3 // indirect
	github.com/gofrs/uuid v3.3.0+incompatible // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/hailocab/go-hostpool v0.0.0-20160125115350-e80d13ce29ed // indirect
	github.com/jinzhu/gorm v1.9.16 // indirect
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/lib/pq v1.8.0 // indirect
	github.com/mattn/go-sqlite3 v1.14.4 // indirect
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/mitchellh/mapstructure v1.3.2 // indirect
	github.com/moby/buildkit v0.7.1-0.20200718032743-4d1f260e8490
	github.com/moby/term v0.0.0-20200915141129-7f0af18e79f2
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.1
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/cobra v1.1.1
	github.com/spf13/pflag v1.0.5
	github.com/theupdateframework/notary v0.6.1
	github.com/tonistiigi/fsutil v0.0.0-20200512175118-ae3a8d753069
	github.com/tonistiigi/go-rosetta v0.0.0-20200727161949-f79598599c5d
	golang.org/x/sync v0.0.0-20200625203802-6e8e738ad208
	golang.org/x/text v0.3.3
	gopkg.in/dancannon/gorethink.v3 v3.0.5 // indirect
	gopkg.in/fatih/pool.v2 v2.0.0 // indirect
	gopkg.in/gorethink/gorethink.v3 v3.0.5 // indirect
	gopkg.in/yaml.v2 v2.2.8
)
