// Copyright (c) 2015 The btcsuite developers
// Copyright (c) 2015-2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//+build !generate

package rpchelp

import "github.com/endurio/ndrd/ndrjson"

// Common return types.
var (
	returnsBool        = []interface{}{(*bool)(nil)}
	returnsNumber      = []interface{}{(*float64)(nil)}
	returnsString      = []interface{}{(*string)(nil)}
	returnsStringArray = []interface{}{(*[]string)(nil)}
	returnsLTRArray    = []interface{}{(*[]ndrjson.ListTransactionsResult)(nil)}
)

// Methods contains all methods and result types that help is generated for,
// for every locale.
var Methods = []struct {
	Method      string
	ResultTypes []interface{}
}{
	{"accountaddressindex", []interface{}{(*int)(nil)}},
	{"accountsyncaddressindex", nil},
	{"addmultisigaddress", returnsString},
	{"addticket", nil},
	{"consolidate", returnsString},
	{"createmultisig", []interface{}{(*ndrjson.CreateMultiSigResult)(nil)}},
	{"createnewaccount", nil},
	{"dumpprivkey", returnsString},
	{"exportwatchingwallet", returnsString},
	{"getaccountaddress", returnsString},
	{"getaccount", returnsString},
	{"getaddressesbyaccount", returnsStringArray},
	{"getbalance", []interface{}{(*ndrjson.GetBalanceResult)(nil)}},
	{"getbestblockhash", returnsString},
	{"getbestblock", []interface{}{(*ndrjson.GetBestBlockResult)(nil)}},
	{"getblockcount", returnsNumber},
	{"getinfo", []interface{}{(*ndrjson.InfoWalletResult)(nil)}},
	{"getmasterpubkey", []interface{}{(*string)(nil)}},
	{"getmultisigoutinfo", []interface{}{(*ndrjson.GetMultisigOutInfoResult)(nil)}},
	{"getnewaddress", returnsString},
	{"getrawchangeaddress", returnsString},
	{"getreceivedbyaccount", returnsNumber},
	{"getreceivedbyaddress", returnsNumber},
	{"getticketfee", returnsNumber},
	{"gettransaction", []interface{}{(*ndrjson.GetTransactionResult)(nil)}},
	{"getunconfirmedbalance", returnsNumber},
	{"getwalletfee", returnsNumber},
	{"help", append(returnsString, returnsString[0])},
	{"importprivkey", nil},
	{"importscript", nil},
	{"keypoolrefill", nil},
	{"listaccounts", []interface{}{(*map[string]float64)(nil)}},
	{"listaddresstransactions", returnsLTRArray},
	{"listalltransactions", returnsLTRArray},
	{"listlockunspent", []interface{}{(*[]ndrjson.TransactionInput)(nil)}},
	{"listreceivedbyaccount", []interface{}{(*[]ndrjson.ListReceivedByAccountResult)(nil)}},
	{"listreceivedbyaddress", []interface{}{(*[]ndrjson.ListReceivedByAddressResult)(nil)}},
	{"listscripts", []interface{}{(*ndrjson.ListScriptsResult)(nil)}},
	{"listsinceblock", []interface{}{(*ndrjson.ListSinceBlockResult)(nil)}},
	{"listtransactions", returnsLTRArray},
	{"listunspent", []interface{}{(*ndrjson.ListUnspentResult)(nil)}},
	{"lockunspent", returnsBool},
	{"redeemmultisigout", []interface{}{(*ndrjson.RedeemMultiSigOutResult)(nil)}},
	{"redeemmultisigouts", []interface{}{(*ndrjson.RedeemMultiSigOutResult)(nil)}},
	{"renameaccount", nil},
	{"rescanwallet", nil},
	{"sendfrom", returnsString},
	{"sendmany", returnsString},
	{"sendtoaddress", returnsString},
	{"sendtomultisig", returnsString},
	{"settxfee", returnsBool},
	{"signmessage", returnsString},
	{"signrawtransaction", []interface{}{(*ndrjson.SignRawTransactionResult)(nil)}},
	{"signrawtransactions", []interface{}{(*ndrjson.SignRawTransactionsResult)(nil)}},
	{"sweepaccount", []interface{}{(*ndrjson.SweepAccountResult)(nil)}},
	{"validateaddress", []interface{}{(*ndrjson.ValidateAddressWalletResult)(nil)}},
	{"verifymessage", returnsBool},
	{"version", []interface{}{(*map[string]ndrjson.VersionResult)(nil)}},
	{"walletinfo", []interface{}{(*ndrjson.WalletInfoResult)(nil)}},
	{"walletislocked", returnsBool},
	{"walletlock", nil},
	{"walletpassphrasechange", nil},
	{"walletpassphrase", nil},
}

// HelpDescs contains the locale-specific help strings along with the locale.
var HelpDescs = []struct {
	Locale   string // Actual locale, e.g. en_US
	GoLocale string // Locale used in Go names, e.g. EnUS
	Descs    map[string]string
}{
	{"en_US", "EnUS", helpDescsEnUS}, // helpdescs_en_US.go
}
