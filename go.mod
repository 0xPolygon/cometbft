module github.com/tendermint/tendermint

go 1.12

require (
	github.com/VividCortex/gohistogram v1.0.0 // indirect
	github.com/Workiva/go-datastructures v1.0.50
	github.com/btcsuite/btcd/btcec/v2 v2.3.2
	github.com/btcsuite/btcutil v0.0.0-20190425235716-9e5f4b9a998d
	github.com/ethereum/go-ethereum v0.0.0-00010101000000-000000000000
	github.com/fortytw2/leaktest v1.3.0
	github.com/go-kit/kit v0.9.0
	github.com/go-logfmt/logfmt v0.5.0
	github.com/gogo/protobuf v1.3.2
	github.com/golang/protobuf v1.5.3
	github.com/gorilla/websocket v1.4.2
	github.com/libp2p/go-buffer-pool v0.0.2
	github.com/magiconair/properties v1.8.1
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.11.1
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475
	github.com/rs/cors v1.7.0
	github.com/snikch/goodman v0.0.0-20171125024755-10e37e294daa
	github.com/spf13/cobra v0.0.3
	github.com/spf13/viper v1.4.0
	github.com/stretchr/testify v1.8.3
	github.com/stumble/gorocksdb v0.0.3 // indirect
	github.com/tendermint/go-amino v0.14.1
	github.com/tendermint/tm-db v0.2.0
	golang.org/x/crypto v0.11.0
	golang.org/x/net v0.12.0
	google.golang.org/grpc v1.58.2
)

replace github.com/ethereum/go-ethereum => github.com/maticnetwork/bor v0.2.16
