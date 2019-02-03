module github.com/endurio/ndrw

require (
	github.com/dchest/siphash v1.2.1 // indirect
	github.com/decred/slog v1.0.0
	github.com/endurio/ndrd/addrmgr v1.0.2
	github.com/endurio/ndrd/blockchain v1.1.1
	github.com/endurio/ndrd/certgen v1.0.2
	github.com/endurio/ndrd/chaincfg v1.2.1
	github.com/endurio/ndrd/chaincfg/chainhash v1.0.1
	github.com/endurio/ndrd/connmgr v1.0.2
	github.com/endurio/ndrd/hdkeychain v1.1.1
	github.com/endurio/ndrd/ndrec v0.0.0-20181212181811-1a370d38d671
	github.com/endurio/ndrd/ndrjson v1.1.0
	github.com/endurio/ndrd/ndrutil v1.2.0
	github.com/endurio/ndrd/rpcclient v1.1.0
	github.com/endurio/ndrd/txscript v1.0.2
	github.com/endurio/ndrd/wire v1.2.0
	github.com/endurio/ndrw/chain v1.1.0
	github.com/endurio/ndrw/errors v1.0.1
	github.com/endurio/ndrw/internal/helpers v1.0.1
	github.com/endurio/ndrw/internal/zero v1.0.1
	github.com/endurio/ndrw/p2p v1.0.1
	github.com/endurio/ndrw/rpc/walletrpc v0.2.0
	github.com/endurio/ndrw/spv v1.1.0
	github.com/endurio/ndrw/version v1.0.1
	github.com/endurio/ndrw/wallet v1.1.0
	github.com/endurio/ndrw/walletseed v1.0.1
	github.com/gorilla/websocket v1.2.0
	github.com/jessevdk/go-flags v1.4.0
	github.com/jrick/logrotate v1.0.0
	golang.org/x/crypto v0.0.0-20181203042331-505ab145d0a9
	golang.org/x/sys v0.0.0-20190102155601-82a175fd1598 // indirect
	google.golang.org/grpc v1.17.0
)

replace (
	github.com/endurio/ndrd => ../ndrd
	github.com/endurio/ndrd/addrmgr => ../ndrd/addrmgr
	github.com/endurio/ndrd/blockchain => ../ndrd/blockchain
	github.com/endurio/ndrd/certgen => ../ndrd/certgen
	github.com/endurio/ndrd/chaincfg => ../ndrd/chaincfg
	github.com/endurio/ndrd/chaincfg/chainhash => ../ndrd/chaincfg/chainhash
	github.com/endurio/ndrd/connmgr => ../ndrd/connmgr
	github.com/endurio/ndrd/database => ../ndrd/database
	github.com/endurio/ndrd/gcs => ../ndrd/gcs
	github.com/endurio/ndrd/hdkeychain => ../ndrd/hdkeychain
	github.com/endurio/ndrd/mempool => ../ndrd/mempool
	github.com/endurio/ndrd/mining => ../ndrd/mining
	github.com/endurio/ndrd/ndrec => ../ndrd/ndrec
	github.com/endurio/ndrd/ndrec/edwards => ../ndrd/ndrec/edwards
	github.com/endurio/ndrd/ndrec/secp256k1 => ../ndrd/ndrec/secp256k1
	github.com/endurio/ndrd/ndrjson => ../ndrd/ndrjson
	github.com/endurio/ndrd/ndrutil => ../ndrd/ndrutil
	github.com/endurio/ndrd/rpcclient => ../ndrd/rpcclient
	github.com/endurio/ndrd/txscript => ../ndrd/txscript
	github.com/endurio/ndrd/wire => ../ndrd/wire
	github.com/endurio/ndrw => ./
	github.com/endurio/ndrw/chain => ./chain
	github.com/endurio/ndrw/deployments => ./deployments
	github.com/endurio/ndrw/errors => ./errors
	github.com/endurio/ndrw/internal/helpers => ./internal/helpers
	github.com/endurio/ndrw/internal/zero => ./internal/zero
	github.com/endurio/ndrw/lru => ./lru
	github.com/endurio/ndrw/p2p => ./p2p
	github.com/endurio/ndrw/pgpwordlist => ./pgpwordlist
	github.com/endurio/ndrw/rpc/walletrpc => ./rpc/walletrpc
	github.com/endurio/ndrw/spv => ./spv
	github.com/endurio/ndrw/validate => ./validate
	github.com/endurio/ndrw/version => ./version
	github.com/endurio/ndrw/wallet => ./wallet
	github.com/endurio/ndrw/walletseed => ./walletseed
)
