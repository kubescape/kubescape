module github.com/kubescape/kubescape/v2

go 1.18

require (
	cloud.google.com/go/containeranalysis v0.4.0
	github.com/armosec/armoapi-go v0.0.119
	github.com/armosec/go-git-url v0.0.15
	github.com/armosec/utils-go v0.0.12
	github.com/armosec/utils-k8s-go v0.0.12
	github.com/briandowns/spinner v1.18.1
	github.com/enescakir/emoji v1.0.0
	github.com/fatih/color v1.13.0
	github.com/francoispqt/gojay v1.2.13
	github.com/go-git/go-git/v5 v5.4.2
	github.com/google/uuid v1.3.0
	github.com/johnfercher/maroto v0.37.0
	github.com/kubescape/go-logger v0.0.6
	github.com/kubescape/k8s-interface v0.0.89
	github.com/kubescape/opa-utils v0.0.204
	github.com/kubescape/rbac-utils v0.0.19
	github.com/libgit2/git2go/v33 v33.0.9
	github.com/mattn/go-isatty v0.0.14
	github.com/mikefarah/yq/v4 v4.29.1
	github.com/olekukonko/tablewriter v0.0.5
	github.com/open-policy-agent/opa v0.45.0
	github.com/owenrumney/go-sarif/v2 v2.1.2
	github.com/spf13/cobra v1.6.1
	github.com/stretchr/testify v1.8.0
	github.com/whilp/git-urls v1.0.0
	golang.org/x/mod v0.6.0-dev.0.20220106191415-9b9b3d81d5e3
	google.golang.org/api v0.85.0
	google.golang.org/genproto v0.0.0-20220708155623-50e5f4832e73
	google.golang.org/protobuf v1.28.1
	gopkg.in/op/go-logging.v1 v1.0.0-20160211212156-b2cb9fa56473
	gopkg.in/yaml.v3 v3.0.1
	helm.sh/helm/v3 v3.9.0
	k8s.io/api v0.25.3
	k8s.io/apimachinery v0.25.3
	k8s.io/client-go v0.25.3
	k8s.io/utils v0.0.0-20220728103510-ee6ede2d64ed
	sigs.k8s.io/kustomize/api v0.11.4
	sigs.k8s.io/kustomize/kyaml v0.13.6
	sigs.k8s.io/yaml v1.3.0
)

require github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect

require (
	cloud.google.com/go/compute v1.7.0 // indirect
	cloud.google.com/go/container v1.2.0 // indirect
	cloud.google.com/go/grafeas v0.2.0 // indirect
	github.com/Azure/azure-sdk-for-go v66.0.0+incompatible // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.11.27 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.20 // indirect
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.11 // indirect
	github.com/Azure/go-autorest/autorest/azure/cli v0.4.5 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.3.1 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/BurntSushi/toml v1.0.0 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.1.1 // indirect
	github.com/Masterminds/sprig/v3 v3.2.2 // indirect
	github.com/Microsoft/go-winio v0.5.1 // indirect
	github.com/OneOfOne/xxhash v1.2.8 // indirect
	github.com/ProtonMail/go-crypto v0.0.0-20210428141323-04723f9f07d7 // indirect
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/a8m/envsubst v1.3.0 // indirect
	github.com/acomagu/bufpipe v1.0.3 // indirect
	github.com/agnivade/levenshtein v1.1.1 // indirect
	github.com/alecthomas/participle/v2 v2.0.0-beta.5 // indirect
	github.com/aws/aws-sdk-go v1.44.51 // indirect
	github.com/aws/aws-sdk-go-v2 v1.16.7 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.15.13 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.12.8 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.12.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.14 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/eks v1.21.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.11.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.16.9 // indirect
	github.com/aws/smithy-go v1.12.0 // indirect
	github.com/boombuler/barcode v1.0.1 // indirect
	github.com/coreos/go-oidc v2.2.1+incompatible // indirect
	github.com/cyphar/filepath-securejoin v0.2.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/docker/docker v20.10.17+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/elliotchance/orderedmap v1.5.0 // indirect
	github.com/emicklei/go-restful/v3 v3.8.0 // indirect
	github.com/emirpasic/gods v1.12.0 // indirect
	github.com/evanphx/json-patch v4.12.0+incompatible // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/go-errors/errors v1.0.1 // indirect
	github.com/go-git/gcfg v1.5.0 // indirect
	github.com/go-git/go-billy/v5 v5.3.1 // indirect
	github.com/go-gota/gota v0.12.0 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.5 // indirect
	github.com/go-openapi/swag v0.19.14 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/goccy/go-json v0.9.11 // indirect
	github.com/goccy/go-yaml v1.9.6 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.2.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/go-cmp v0.5.8 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.1.0 // indirect
	github.com/googleapis/gax-go/v2 v2.4.0 // indirect
	github.com/huandu/xstrings v1.3.2 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jinzhu/copier v0.3.5 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/jung-kurt/gofpdf v1.16.2 // indirect
	github.com/kevinburke/ssh_config v0.0.0-20201106050909-4977a11b4351 // indirect
	github.com/magiconair/properties v1.8.6 // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-runewidth v0.0.9 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/monochromegane/go-gitignore v0.0.0-20200626010858-205db1a8cc00 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.3-0.20211202183452-c5a74bcca799 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/pquerna/cachecontrol v0.1.0 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20200313005456-10cdbea86bc0 // indirect
	github.com/ruudk/golang-pdf417 v0.0.0-20181029194003-1af4ab5afa58 // indirect
	github.com/sergi/go-diff v1.1.0 // indirect
	github.com/shopspring/decimal v1.2.0 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tchap/go-patricia/v2 v2.3.1 // indirect
	github.com/xanzy/ssh-agent v0.3.0 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/xlab/treeprint v0.0.0-20181112141820-a009c3971eca // indirect
	github.com/yashtewari/glob-intersection v0.1.0 // indirect
	go.opencensus.io v0.23.0 // indirect
	go.starlark.net v0.0.0-20200306205701-8dd3e2ee1dd5 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.22.0 // indirect
	golang.org/x/crypto v0.0.0-20220525230936-793ad666bf5e // indirect
	golang.org/x/net v0.0.0-20220909164309-bea034e7d591 // indirect
	golang.org/x/oauth2 v0.0.0-20220630143837-2104d58473e0 // indirect
	golang.org/x/sys v0.0.0-20220829200755-d48e67d00261 // indirect
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211 // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/time v0.0.0-20220210224613-90d013bbcef8 // indirect
	golang.org/x/xerrors v0.0.0-20220609144429-65e65417b02f // indirect
	gonum.org/v1/gonum v0.9.1 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/grpc v1.49.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/apiextensions-apiserver v0.24.2 // indirect
	k8s.io/klog/v2 v2.70.1 // indirect
	k8s.io/kube-openapi v0.0.0-20220803162953-67bda5d908f1 // indirect
	sigs.k8s.io/controller-runtime v0.12.3 // indirect
	sigs.k8s.io/json v0.0.0-20220713155537-f223a00ba0e2 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
)

replace github.com/libgit2/git2go/v33 => ./git2go
