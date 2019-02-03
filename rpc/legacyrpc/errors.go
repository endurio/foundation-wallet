// Copyright (c) 2013-2015 The btcsuite developers
// Copyright (c) 2016-2018 The Decred developers
// Copyright (c) 2018-2019 The Endurio developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacyrpc

import (
	"fmt"

	"github.com/endurio/ndrd/ndrjson"
	"github.com/endurio/ndrw/errors"
)

func convertError(err error) *ndrjson.RPCError {
	if err, ok := err.(*ndrjson.RPCError); ok {
		return err
	}

	code := ndrjson.ErrRPCWallet
	if err, ok := err.(*errors.Error); ok {
		switch err.Kind {
		case errors.Bug:
			code = ndrjson.ErrRPCInternal.Code
		case errors.Encoding:
			code = ndrjson.ErrRPCInvalidParameter
		case errors.Locked:
			code = ndrjson.ErrRPCWalletUnlockNeeded
		case errors.Passphrase:
			code = ndrjson.ErrRPCWalletPassphraseIncorrect
		case errors.NoPeers:
			code = ndrjson.ErrRPCClientNotConnected
		case errors.InsufficientBalance:
			code = ndrjson.ErrRPCWalletInsufficientFunds
		}
	}
	return &ndrjson.RPCError{
		Code:    code,
		Message: err.Error(),
	}
}

func rpcError(code ndrjson.RPCErrorCode, err error) *ndrjson.RPCError {
	return &ndrjson.RPCError{
		Code:    code,
		Message: err.Error(),
	}
}

func rpcErrorf(code ndrjson.RPCErrorCode, format string, args ...interface{}) *ndrjson.RPCError {
	return &ndrjson.RPCError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

// Errors variables that are defined once here to avoid duplication.
var (
	errUnloadedWallet = &ndrjson.RPCError{
		Code:    ndrjson.ErrRPCWallet,
		Message: "request requires a wallet but wallet has not loaded yet",
	}

	errRPCClientNotConnected = &ndrjson.RPCError{
		Code:    ndrjson.ErrRPCClientNotConnected,
		Message: "disconnected from consensus RPC",
	}

	errNoNetwork = &ndrjson.RPCError{
		Code:    ndrjson.ErrRPCClientNotConnected,
		Message: "disconnected from network",
	}

	errAccountNotFound = &ndrjson.RPCError{
		Code:    ndrjson.ErrRPCWalletInvalidAccountName,
		Message: "account not found",
	}

	errAddressNotInWallet = &ndrjson.RPCError{
		Code:    ndrjson.ErrRPCWallet,
		Message: "address not found in wallet",
	}

	errNotImportedAccount = &ndrjson.RPCError{
		Code:    ndrjson.ErrRPCWallet,
		Message: "imported addresses must belong to the imported account",
	}

	errNeedPositiveAmount = &ndrjson.RPCError{
		Code:    ndrjson.ErrRPCInvalidParameter,
		Message: "amount must be positive",
	}

	errWalletUnlockNeeded = &ndrjson.RPCError{
		Code:    ndrjson.ErrRPCWalletUnlockNeeded,
		Message: "enter the wallet passphrase with walletpassphrase first",
	}

	errReservedAccountName = &ndrjson.RPCError{
		Code:    ndrjson.ErrRPCInvalidParameter,
		Message: "account name is reserved by RPC server",
	}
)
