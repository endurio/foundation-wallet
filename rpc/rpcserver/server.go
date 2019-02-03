// Copyright (c) 2015-2016 The btcsuite developers
// Copyright (c) 2016-2017 The Decred developers
// Copyright (c) 2018-2019 The Endurio developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package rpcserver implements the RPC API and is used by the main package to
// start gRPC services.
//
// Full documentation of the API implemented by this package is maintained in a
// language-agnostic document:
//
//   https://github.com/endurio/ndrw/blob/master/rpc/documentation/api.md
//
// Any API changes must be performed according to the steps listed here:
//
//   https://github.com/endurio/ndrw/blob/master/rpc/documentation/serverchanges.md
package rpcserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/endurio/ndrd/addrmgr"
	"github.com/endurio/ndrd/chaincfg"
	"github.com/endurio/ndrd/chaincfg/chainhash"
	"github.com/endurio/ndrd/hdkeychain"
	"github.com/endurio/ndrd/ndrec"
	"github.com/endurio/ndrd/ndrutil"
	"github.com/endurio/ndrd/rpcclient"
	"github.com/endurio/ndrd/txscript"
	"github.com/endurio/ndrd/wire"
	"github.com/endurio/ndrw/chain"
	"github.com/endurio/ndrw/errors"
	"github.com/endurio/ndrw/internal/cfgutil"
	h "github.com/endurio/ndrw/internal/helpers"
	"github.com/endurio/ndrw/internal/zero"
	"github.com/endurio/ndrw/loader"
	"github.com/endurio/ndrw/netparams"
	"github.com/endurio/ndrw/p2p"
	pb "github.com/endurio/ndrw/rpc/walletrpc"
	"github.com/endurio/ndrw/spv"
	"github.com/endurio/ndrw/wallet"
	"github.com/endurio/ndrw/wallet/txauthor"
	"github.com/endurio/ndrw/wallet/txrules"
	"github.com/endurio/ndrw/wallet/udb"
	"github.com/endurio/ndrw/walletseed"
)

// Public API version constants
const (
	semverString = "5.6.0"
	semverMajor  = 5
	semverMinor  = 6
	semverPatch  = 0
)

// translateError creates a new gRPC error with an appropiate error code for
// recognized errors.
//
// This function is by no means complete and should be expanded based on other
// known errors.  Any RPC handler not returning a gRPC error (with status.Errorf)
// should return this result instead.
func translateError(err error) error {
	code := errorCode(err)
	return status.Errorf(code, "%s", err.Error())
}

func errorCode(err error) codes.Code {
	var inner error
	if err, ok := err.(*errors.Error); ok {
		switch err.Kind {
		case errors.Bug:
		case errors.Invalid:
			return codes.InvalidArgument
		case errors.Permission:
			return codes.PermissionDenied
		case errors.IO:
		case errors.Exist:
			return codes.AlreadyExists
		case errors.NotExist:
			return codes.NotFound
		case errors.Encoding:
		case errors.Crypto:
			return codes.DataLoss
		case errors.Locked:
			return codes.FailedPrecondition
		case errors.Passphrase:
			return codes.InvalidArgument
		case errors.Seed:
			return codes.InvalidArgument
		case errors.WatchingOnly:
			return codes.Unimplemented
		case errors.InsufficientBalance:
			return codes.ResourceExhausted
		case errors.ScriptFailure:
		case errors.Policy:
		case errors.DoubleSpend:
		case errors.Protocol:
		case errors.NoPeers:
			return codes.Unavailable
		default:
			inner = err.Err
			for {
				err, ok := inner.(*errors.Error)
				if !ok {
					break
				}
				inner = err.Err
			}
		}
	}
	switch inner {
	case hdkeychain.ErrInvalidSeedLen:
		return codes.InvalidArgument
	}
	return codes.Unknown
}

// decodeAddress decodes an address and verifies it is intended for the active
// network.  This should be used preferred to direct usage of
// ndrutil.DecodeAddress, which does not perform the network check.
func decodeAddress(a string, params *chaincfg.Params) (ndrutil.Address, error) {
	addr, err := ndrutil.DecodeAddress(a)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid address %v: %v", a, err)
	}
	if !addr.IsForNet(params) {
		return nil, status.Errorf(codes.InvalidArgument,
			"address %v is not intended for use on %v", a, params.Name)
	}
	return addr, nil
}

func decodeHashes(in [][]byte) ([]*chainhash.Hash, error) {
	out := make([]*chainhash.Hash, len(in))
	var err error
	for i, h := range in {
		out[i], err = chainhash.NewHash(h)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "hash (hex %x): %v", h, err)
		}
	}
	return out, nil
}

// versionServer provides RPC clients with the ability to query the RPC server
// version.
type versionServer struct{}

// walletServer provides wallet services for RPC clients.
type walletServer struct {
	ready  uint32 // atomic
	wallet *wallet.Wallet
}

// loaderServer provides RPC clients with the ability to load and close wallets,
// as well as establishing a RPC connection to a ndrd consensus server.
type loaderServer struct {
	ready     uint32 // atomic
	loader    *loader.Loader
	activeNet *netparams.Params
	rpcClient *chain.RPCClient
	mu        sync.Mutex
}

// seedServer provides RPC clients with the ability to generate secure random
// seeds encoded in both binary and human-readable formats, and decode any
// human-readable input back to binary.
type seedServer struct{}

// messageVerificationServer provides RPC clients with the ability to verify
// that a message was signed using the private key of a particular address.
type messageVerificationServer struct{}

type decodeMessageServer struct {
	chainParams *chaincfg.Params
}

// Singleton implementations of each service.  Not all services are immediately
// usable.
var (
	versionService             versionServer
	walletService              walletServer
	loaderService              loaderServer
	seedService                seedServer
	messageVerificationService messageVerificationServer
	decodeMessageService       decodeMessageServer
)

// RegisterServices registers implementations of each gRPC service and registers
// it with the server.  Not all service are ready to be used after registration.
func RegisterServices(server *grpc.Server) {
	pb.RegisterVersionServiceServer(server, &versionService)
	pb.RegisterWalletLoaderServiceServer(server, &loaderService)
	pb.RegisterSeedServiceServer(server, &seedService)
	pb.RegisterMessageVerificationServiceServer(server, &messageVerificationService)
	pb.RegisterDecodeMessageServiceServer(server, &decodeMessageService)
}

var serviceMap = map[string]interface{}{
	"walletrpc.VersionService":             &versionService,
	"walletrpc.WalletService":              &walletService,
	"walletrpc.WalletLoaderService":        &loaderService,
	"walletrpc.SeedService":                &seedService,
	"walletrpc.MessageVerificationService": &messageVerificationService,
	"walletrpc.DecodeMessageService":       &decodeMessageService,
}

// ServiceReady returns nil when the service is ready and a gRPC error when not.
func ServiceReady(service string) error {
	s, ok := serviceMap[service]
	if !ok {
		return status.Errorf(codes.Unimplemented, "service %s not found", service)
	}
	type readyChecker interface {
		checkReady() bool
	}
	ready := true
	r, ok := s.(readyChecker)
	if ok {
		ready = r.checkReady()
	}
	if !ready {
		return status.Errorf(codes.FailedPrecondition, "service %v is not ready", service)
	}
	return nil
}

func (*versionServer) Version(ctx context.Context, req *pb.VersionRequest) (*pb.VersionResponse, error) {
	return &pb.VersionResponse{
		VersionString: semverString,
		Major:         semverMajor,
		Minor:         semverMinor,
		Patch:         semverPatch,
	}, nil
}

// StartWalletService starts the WalletService.
func StartWalletService(server *grpc.Server, wallet *wallet.Wallet) {
	walletService.wallet = wallet
	if atomic.SwapUint32(&walletService.ready, 1) != 0 {
		panic("service already started")
	}
}

func (s *walletServer) checkReady() bool {
	return atomic.LoadUint32(&s.ready) != 0
}

// requireNetworkBackend checks whether the wallet has been associated with the
// consensus server RPC client, returning a gRPC error when it is not.
func (s *walletServer) requireNetworkBackend() (wallet.NetworkBackend, error) {
	n, err := s.wallet.NetworkBackend()
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"wallet is not associated with a consensus server RPC client")
	}
	return n, nil
}

func (s *walletServer) Ping(ctx context.Context, req *pb.PingRequest) (*pb.PingResponse, error) {
	return &pb.PingResponse{}, nil
}

func (s *walletServer) Network(ctx context.Context, req *pb.NetworkRequest) (
	*pb.NetworkResponse, error) {

	return &pb.NetworkResponse{ActiveNetwork: uint32(s.wallet.ChainParams().Net)}, nil
}

func (s *walletServer) AccountNumber(ctx context.Context, req *pb.AccountNumberRequest) (
	*pb.AccountNumberResponse, error) {

	accountNum, err := s.wallet.AccountNumber(req.AccountName)
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.AccountNumberResponse{AccountNumber: accountNum}, nil
}

func (s *walletServer) Accounts(ctx context.Context, req *pb.AccountsRequest) (*pb.AccountsResponse, error) {
	resp, err := s.wallet.Accounts()
	if err != nil {
		return nil, translateError(err)
	}
	accounts := make([]*pb.AccountsResponse_Account, len(resp.Accounts))
	for i := range resp.Accounts {
		a := &resp.Accounts[i]
		accounts[i] = &pb.AccountsResponse_Account{
			AccountNumber:    a.AccountNumber,
			AccountName:      a.AccountName,
			TotalBalance:     int64(a.TotalBalance),
			ExternalKeyCount: a.LastUsedExternalIndex + 20, // Add gap limit
			InternalKeyCount: a.LastUsedInternalIndex + 20,
			ImportedKeyCount: a.ImportedKeyCount,
		}
	}
	return &pb.AccountsResponse{
		Accounts:           accounts,
		CurrentBlockHash:   resp.CurrentBlockHash[:],
		CurrentBlockHeight: resp.CurrentBlockHeight,
	}, nil
}

func (s *walletServer) RenameAccount(ctx context.Context, req *pb.RenameAccountRequest) (
	*pb.RenameAccountResponse, error) {

	err := s.wallet.RenameAccount(req.AccountNumber, req.NewName)
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.RenameAccountResponse{}, nil
}

func (s *walletServer) PublishUnminedTransactions(ctx context.Context, req *pb.PublishUnminedTransactionsRequest) (
	*pb.PublishUnminedTransactionsResponse, error) {
	n, err := s.requireNetworkBackend()
	if err != nil {
		return nil, err
	}
	err = s.wallet.PublishUnminedTransactions(ctx, n)
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.PublishUnminedTransactionsResponse{}, nil
}

func (s *walletServer) Rescan(req *pb.RescanRequest, svr pb.WalletService_RescanServer) error {
	n, err := s.requireNetworkBackend()
	if err != nil {
		return err
	}

	var blockID *wallet.BlockIdentifier
	switch {
	case req.BeginHash != nil && req.BeginHeight != 0:
		return status.Errorf(codes.InvalidArgument, "begin hash and height must not be set together")
	case req.BeginHeight < 0:
		return status.Errorf(codes.InvalidArgument, "begin height must be non-negative")
	case req.BeginHash != nil:
		blockHash, err := chainhash.NewHash(req.BeginHash)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "block hash has invalid length")
		}
		blockID = wallet.NewBlockIdentifierFromHash(blockHash)
	default:
		blockID = wallet.NewBlockIdentifierFromHeight(req.BeginHeight)
	}

	b, err := s.wallet.BlockInfo(blockID)
	if err != nil {
		return translateError(err)
	}

	progress := make(chan wallet.RescanProgress, 1)
	go s.wallet.RescanProgressFromHeight(svr.Context(), n, b.Height, progress)

	for p := range progress {
		if p.Err != nil {
			return translateError(p.Err)
		}
		resp := &pb.RescanResponse{RescannedThrough: p.ScannedThrough}
		err := svr.Send(resp)
		if err != nil {
			return translateError(err)
		}
	}
	// finished or cancelled rescan without error
	select {
	case <-svr.Context().Done():
		return status.Errorf(codes.Canceled, "rescan canceled")
	default:
		return nil
	}
}

func (s *walletServer) NextAccount(ctx context.Context, req *pb.NextAccountRequest) (
	*pb.NextAccountResponse, error) {

	defer zero.Bytes(req.Passphrase)

	if req.AccountName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "account name may not be empty")
	}

	lock := make(chan time.Time, 1)
	defer func() {
		lock <- time.Time{} // send matters, not the value
	}()
	err := s.wallet.Unlock(req.Passphrase, lock)
	if err != nil {
		return nil, translateError(err)
	}

	account, err := s.wallet.NextAccount(req.AccountName)
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.NextAccountResponse{AccountNumber: account}, nil
}

func (s *walletServer) NextAddress(ctx context.Context, req *pb.NextAddressRequest) (
	*pb.NextAddressResponse, error) {

	var callOpts []wallet.NextAddressCallOption
	switch req.GapPolicy {
	case pb.NextAddressRequest_GAP_POLICY_UNSPECIFIED:
	case pb.NextAddressRequest_GAP_POLICY_ERROR:
		callOpts = append(callOpts, wallet.WithGapPolicyError())
	case pb.NextAddressRequest_GAP_POLICY_IGNORE:
		callOpts = append(callOpts, wallet.WithGapPolicyIgnore())
	case pb.NextAddressRequest_GAP_POLICY_WRAP:
		callOpts = append(callOpts, wallet.WithGapPolicyWrap())
	default:
		return nil, status.Errorf(codes.InvalidArgument, "gap_policy=%v", req.GapPolicy)
	}

	var (
		addr ndrutil.Address
		err  error
	)
	switch req.Kind {
	case pb.NextAddressRequest_BIP0044_EXTERNAL:
		addr, err = s.wallet.NewExternalAddress(req.Account, callOpts...)
		if err != nil {
			return nil, translateError(err)
		}
	case pb.NextAddressRequest_BIP0044_INTERNAL:
		addr, err = s.wallet.NewInternalAddress(req.Account, callOpts...)
		if err != nil {
			return nil, translateError(err)
		}
	default:
		return nil, status.Errorf(codes.InvalidArgument, "kind=%v", req.Kind)
	}
	if err != nil {
		return nil, translateError(err)
	}

	pubKey, err := s.wallet.PubKeyForAddress(addr)
	if err != nil {
		return nil, translateError(err)
	}
	pubKeyAddr, err := ndrutil.NewAddressSecpPubKey(pubKey.Serialize(), s.wallet.ChainParams())
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.NextAddressResponse{
		Address:   addr.EncodeAddress(),
		PublicKey: pubKeyAddr.String(),
	}, nil
}

func (s *walletServer) ImportPrivateKey(ctx context.Context, req *pb.ImportPrivateKeyRequest) (
	*pb.ImportPrivateKeyResponse, error) {

	defer zero.Bytes(req.Passphrase)

	wif, err := ndrutil.DecodeWIF(req.PrivateKeyWif)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument,
			"Invalid WIF-encoded private key: %v", err)
	}

	lock := make(chan time.Time, 1)
	defer func() {
		lock <- time.Time{} // send matters, not the value
	}()
	err = s.wallet.Unlock(req.Passphrase, lock)
	if err != nil {
		return nil, translateError(err)
	}

	// At the moment, only the special-cased import account can be used to
	// import keys.
	if req.Account != udb.ImportedAddrAccount {
		return nil, status.Errorf(codes.InvalidArgument,
			"Only the imported account accepts private key imports")
	}

	if req.ScanFrom < 0 {
		return nil, status.Errorf(codes.InvalidArgument,
			"Attempted to scan from a negative block height")
	}

	if req.ScanFrom > 0 && req.Rescan {
		return nil, status.Errorf(codes.InvalidArgument,
			"Passed a rescan height without rescan set")
	}

	n, err := s.requireNetworkBackend()
	if err != nil {
		return nil, err
	}

	_, err = s.wallet.ImportPrivateKey(wif)
	if err != nil {
		return nil, translateError(err)
	}

	if req.Rescan {
		go s.wallet.RescanFromHeight(context.Background(), n, req.ScanFrom)
	}

	return &pb.ImportPrivateKeyResponse{}, nil
}

func (s *walletServer) ImportScript(ctx context.Context,
	req *pb.ImportScriptRequest) (*pb.ImportScriptResponse, error) {

	defer zero.Bytes(req.Passphrase)

	// TODO: Rather than assuming the "default" version, it must be a parameter
	// to the request.
	sc, addrs, requiredSigs, err := txscript.ExtractPkScriptAddrs(
		txscript.DefaultScriptVersion, req.Script, s.wallet.ChainParams())
	if err != nil && req.RequireRedeemable {
		return nil, status.Errorf(codes.FailedPrecondition,
			"The script is not redeemable by the wallet")
	}
	ownAddrs := 0
	for _, a := range addrs {
		haveAddr, err := s.wallet.HaveAddress(a)
		if err != nil {
			return nil, translateError(err)
		}
		if haveAddr {
			ownAddrs++
		}
	}
	redeemable := sc == txscript.MultiSigTy && ownAddrs >= requiredSigs
	if !redeemable && req.RequireRedeemable {
		return nil, status.Errorf(codes.FailedPrecondition,
			"The script is not redeemable by the wallet")
	}

	if !s.wallet.Manager.WatchingOnly() {
		lock := make(chan time.Time, 1)
		defer func() {
			lock <- time.Time{} // send matters, not the value
		}()
		err = s.wallet.Unlock(req.Passphrase, lock)
		if err != nil {
			return nil, translateError(err)
		}
	}

	if req.ScanFrom < 0 {
		return nil, status.Errorf(codes.InvalidArgument,
			"Attempted to scan from a negative block height")
	}

	if req.ScanFrom > 0 && req.Rescan {
		return nil, status.Errorf(codes.InvalidArgument,
			"Passed a rescan height without rescan set")
	}

	n, err := s.requireNetworkBackend()
	if err != nil {
		return nil, err
	}

	err = s.wallet.ImportScript(req.Script)
	if err != nil {
		return nil, translateError(err)
	}

	if req.Rescan {
		go s.wallet.RescanFromHeight(context.Background(), n, req.ScanFrom)
	}

	p2sh, err := ndrutil.NewAddressScriptHash(req.Script, s.wallet.ChainParams())
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.ImportScriptResponse{P2ShAddress: p2sh.String(), Redeemable: redeemable}, nil
}

func (s *walletServer) Balance(ctx context.Context, req *pb.BalanceRequest) (
	*pb.BalanceResponse, error) {

	account := req.AccountNumber
	reqConfs := req.RequiredConfirmations
	bals, err := s.wallet.CalculateAccountBalance(account, reqConfs)
	if err != nil {
		return nil, translateError(err)
	}

	// TODO: Spendable currently includes multisig outputs that may not
	// actually be spendable without additional keys.
	resp := &pb.BalanceResponse{
		Total:          int64(bals.Total),
		Spendable:      int64(bals.Spendable),
		ImmatureReward: int64(bals.ImmatureCoinbaseRewards),
		Unconfirmed:    int64(bals.Unconfirmed),
	}
	return resp, nil
}

// scriptChangeSource is a ChangeSource which is used to
// receive all correlated previous input value.
type scriptChangeSource struct {
	version uint16
	script  []byte
}

func (src *scriptChangeSource) Script() ([]byte, uint16, error) {
	return src.script, src.version, nil
}

func (src *scriptChangeSource) ScriptSize() int {
	return len(src.script)
}

func makeScriptChangeSource(address string, version uint16) (*scriptChangeSource, error) {
	destinationAddress, err := ndrutil.DecodeAddress(address)
	if err != nil {
		return nil, err
	}

	script, err := txscript.PayToAddrScript(destinationAddress)
	if err != nil {
		return nil, err
	}

	source := &scriptChangeSource{
		version: version,
		script:  script,
	}

	return source, nil
}

func (s *walletServer) SweepAccount(ctx context.Context, req *pb.SweepAccountRequest) (*pb.SweepAccountResponse, error) {
	feePerKb := s.wallet.RelayFee()

	// Use provided fee per Kb if specified.
	if req.FeePerKb < 0 {
		return nil, status.Errorf(codes.InvalidArgument, "%s",
			"fee per kb argument cannot be negative")
	}

	if req.FeePerKb > 0 {
		var err error
		feePerKb, err = ndrutil.NewAmount(req.FeePerKb)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
	}

	account, err := s.wallet.AccountNumber(req.SourceAccount)
	if err != nil {
		return nil, translateError(err)
	}

	changeSource, err := makeScriptChangeSource(req.DestinationAddress,
		txscript.DefaultScriptVersion)
	if err != nil {
		return nil, translateError(err)
	}

	tx, err := s.wallet.NewUnsignedTransaction(nil, feePerKb, account,
		int32(req.RequiredConfirmations), wallet.OutputSelectionAlgorithmAll,
		changeSource)
	if err != nil {
		return nil, translateError(err)
	}

	var txBuf bytes.Buffer
	txBuf.Grow(tx.Tx.SerializeSize())
	err = tx.Tx.Serialize(&txBuf)
	if err != nil {
		return nil, translateError(err)
	}

	res := &pb.SweepAccountResponse{
		UnsignedTransaction:       txBuf.Bytes(),
		TotalPreviousOutputAmount: int64(tx.TotalInput),
		TotalOutputAmount:         int64(h.SumOutputValues(tx.Tx.TxOut)),
		EstimatedSignedSize:       uint32(tx.EstimatedSignedSerializeSize),
	}

	return res, nil
}

func (s *walletServer) BlockInfo(ctx context.Context, req *pb.BlockInfoRequest) (*pb.BlockInfoResponse, error) {
	var blockID *wallet.BlockIdentifier
	switch {
	case req.BlockHash != nil && req.BlockHeight != 0:
		return nil, status.Errorf(codes.InvalidArgument, "block hash and height must not be set together")
	case req.BlockHash != nil:
		blockHash, err := chainhash.NewHash(req.BlockHash)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "block hash has invalid length")
		}
		blockID = wallet.NewBlockIdentifierFromHash(blockHash)
	default:
		blockID = wallet.NewBlockIdentifierFromHeight(req.BlockHeight)
	}

	b, err := s.wallet.BlockInfo(blockID)
	if err != nil {
		return nil, translateError(err)
	}

	header := new(wire.BlockHeader)
	err = header.Deserialize(bytes.NewReader(b.Header[:]))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to deserialize saved block header: %v", err)
	}

	return &pb.BlockInfoResponse{
		BlockHash:     b.Hash[:],
		BlockHeight:   b.Height,
		Confirmations: b.Confirmations,
		Timestamp:     b.Timestamp,
		BlockHeader:   b.Header[:],
	}, nil
}

func (s *walletServer) UnspentOutputs(req *pb.UnspentOutputsRequest, svr pb.WalletService_UnspentOutputsServer) error {
	policy := wallet.OutputSelectionPolicy{
		Account:               req.Account,
		RequiredConfirmations: req.RequiredConfirmations,
	}
	inputDetail, err := s.wallet.SelectInputs(ndrutil.Amount(req.TargetAmount), policy)
	// Do not return errors to caller when there was insufficient spendable
	// outputs available for the target amount.
	if err != nil && !errors.Is(errors.InsufficientBalance, err) {
		return translateError(err)
	}

	var sum int64
	for i, input := range inputDetail.Inputs {
		select {
		case <-svr.Context().Done():
			return status.Errorf(codes.Canceled, "unspentoutputs cancelled")
		default:
			outputInfo, err := s.wallet.OutputInfo(&input.PreviousOutPoint)
			if err != nil {
				return translateError(err)
			}
			unspentOutput := &pb.UnspentOutputResponse{
				TransactionHash: input.PreviousOutPoint.Hash[:],
				OutputIndex:     input.PreviousOutPoint.Index,
				Amount:          int64(outputInfo.Amount),
				PkScript:        inputDetail.Scripts[i],
				ReceiveTime:     outputInfo.Received.Unix(),
				FromCoinbase:    outputInfo.FromCoinbase,
			}

			sum += unspentOutput.Amount
			unspentOutput.AmountSum = sum

			err = svr.Send(unspentOutput)
			if err != nil {
				return translateError(err)
			}
		}
	}
	return nil
}

func (s *walletServer) FundTransaction(ctx context.Context, req *pb.FundTransactionRequest) (
	*pb.FundTransactionResponse, error) {

	policy := wallet.OutputSelectionPolicy{
		Account:               req.Account,
		RequiredConfirmations: req.RequiredConfirmations,
	}
	inputDetail, err := s.wallet.SelectInputs(ndrutil.Amount(req.TargetAmount), policy)
	// Do not return errors to caller when there was insufficient spendable
	// outputs available for the target amount.
	if err != nil && !errors.Is(errors.InsufficientBalance, err) {
		return nil, translateError(err)
	}

	selectedOutputs := make([]*pb.FundTransactionResponse_PreviousOutput, len(inputDetail.Inputs))
	for i, input := range inputDetail.Inputs {
		outputInfo, err := s.wallet.OutputInfo(&input.PreviousOutPoint)
		if err != nil {
			return nil, translateError(err)
		}
		selectedOutputs[i] = &pb.FundTransactionResponse_PreviousOutput{
			TransactionHash: input.PreviousOutPoint.Hash[:],
			OutputIndex:     input.PreviousOutPoint.Index,
			Amount:          int64(outputInfo.Amount),
			PkScript:        inputDetail.Scripts[i],
			ReceiveTime:     outputInfo.Received.Unix(),
			FromCoinbase:    outputInfo.FromCoinbase,
		}
	}

	var changeScript []byte
	if req.IncludeChangeScript && inputDetail.Amount > ndrutil.Amount(req.TargetAmount) {
		changeAddr, err := s.wallet.NewChangeAddress(req.Account)
		if err != nil {
			return nil, translateError(err)
		}
		changeScript, err = txscript.PayToAddrScript(changeAddr)
		if err != nil {
			return nil, translateError(err)
		}
	}

	return &pb.FundTransactionResponse{
		SelectedOutputs: selectedOutputs,
		TotalAmount:     int64(inputDetail.Amount),
		ChangePkScript:  changeScript,
	}, nil
}

func decodeDestination(dest *pb.ConstructTransactionRequest_OutputDestination,
	chainParams *chaincfg.Params) (pkScript []byte, version uint16, err error) {

	switch {
	case dest == nil:
		fallthrough
	default:
		return nil, 0, status.Errorf(codes.InvalidArgument, "unknown or missing output destination")

	case dest.Address != "":
		addr, err := decodeAddress(dest.Address, chainParams)
		if err != nil {
			return nil, 0, err
		}
		pkScript, err = txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, 0, translateError(err)
		}
		version = txscript.DefaultScriptVersion
		return pkScript, version, nil
	case dest.Script != nil:
		if dest.ScriptVersion > uint32(^uint16(0)) {
			return nil, 0, status.Errorf(codes.InvalidArgument, "script_version overflows uint16")
		}
		return dest.Script, uint16(dest.ScriptVersion), nil
	}
}

type txChangeSource struct {
	version uint16
	script  []byte
}

func (src *txChangeSource) Script() ([]byte, uint16, error) {
	return src.script, src.version, nil
}

func (src *txChangeSource) ScriptSize() int {
	return len(src.script)
}

func makeTxChangeSource(destination *pb.ConstructTransactionRequest_OutputDestination,
	chainParams *chaincfg.Params) (*txChangeSource, error) {
	script, version, err := decodeDestination(destination, chainParams)
	if err != nil {
		return nil, err
	}
	changeSource := &txChangeSource{
		script:  script,
		version: version,
	}
	return changeSource, nil
}

func (s *walletServer) ConstructTransaction(ctx context.Context, req *pb.ConstructTransactionRequest) (
	*pb.ConstructTransactionResponse, error) {

	chainParams := s.wallet.ChainParams()

	if len(req.NonChangeOutputs) == 0 && req.ChangeDestination == nil {
		return nil, status.Errorf(codes.InvalidArgument,
			"non_change_outputs and change_destination may not both be empty or null")
	}

	outputs := make([]*wire.TxOut, 0, len(req.NonChangeOutputs))
	for _, o := range req.NonChangeOutputs {
		script, version, err := decodeDestination(o.Destination, chainParams)
		if err != nil {
			return nil, err
		}
		output := &wire.TxOut{
			Value:    o.Amount,
			Version:  version,
			PkScript: script,
		}
		outputs = append(outputs, output)
	}

	var algo wallet.OutputSelectionAlgorithm
	switch req.OutputSelectionAlgorithm {
	case pb.ConstructTransactionRequest_UNSPECIFIED:
		algo = wallet.OutputSelectionAlgorithmDefault
	case pb.ConstructTransactionRequest_ALL:
		algo = wallet.OutputSelectionAlgorithmAll
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown output selection algorithm")
	}

	feePerKb := txrules.DefaultRelayFeePerKb
	if req.FeePerKb != 0 {
		feePerKb = ndrutil.Amount(req.FeePerKb)
	}

	var changeSource txauthor.ChangeSource
	var err error
	if req.ChangeDestination != nil {
		changeSource, err = makeTxChangeSource(req.ChangeDestination, chainParams)
		if err != nil {
			return nil, translateError(err)
		}
	}

	tx, err := s.wallet.NewUnsignedTransaction(outputs, feePerKb, req.SourceAccount,
		req.RequiredConfirmations, algo, changeSource)
	if err != nil {
		return nil, translateError(err)
	}

	if tx.ChangeIndex >= 0 {
		tx.RandomizeChangePosition()
	}

	var txBuf bytes.Buffer
	txBuf.Grow(tx.Tx.SerializeSize())
	err = tx.Tx.Serialize(&txBuf)
	if err != nil {
		return nil, translateError(err)
	}

	res := &pb.ConstructTransactionResponse{
		UnsignedTransaction:       txBuf.Bytes(),
		TotalPreviousOutputAmount: int64(tx.TotalInput),
		TotalOutputAmount:         int64(h.SumOutputValues(tx.Tx.TxOut)),
		EstimatedSignedSize:       uint32(tx.EstimatedSignedSerializeSize),
		ChangeIndex:               int32(tx.ChangeIndex),
	}
	return res, nil
}

func (s *walletServer) GetAccountExtendedPubKey(ctx context.Context, req *pb.GetAccountExtendedPubKeyRequest) (*pb.GetAccountExtendedPubKeyResponse, error) {
	accExtendedPubKey, err := s.wallet.MasterPubKey(req.AccountNumber)
	if err != nil {
		return nil, err
	}
	res := &pb.GetAccountExtendedPubKeyResponse{
		AccExtendedPubKey: accExtendedPubKey.String(),
	}
	return res, nil
}

func (s *walletServer) GetTransaction(ctx context.Context, req *pb.GetTransactionRequest) (*pb.GetTransactionResponse, error) {
	txHash, err := chainhash.NewHash(req.TransactionHash)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "transaction_hash has invalid length")
	}

	txSummary, confs, blockHash, err := s.wallet.TransactionSummary(txHash)
	if err != nil {
		return nil, translateError(err)
	}
	resp := &pb.GetTransactionResponse{
		Transaction:   marshalTransactionDetails(txSummary),
		Confirmations: confs,
	}
	if blockHash != nil {
		resp.BlockHash = blockHash[:]
	}
	return resp, nil
}

// BUGS:
// - MinimumRecentTransactions is ignored.
// - Wrong error codes when a block height or hash is not recognized
func (s *walletServer) GetTransactions(req *pb.GetTransactionsRequest,
	server pb.WalletService_GetTransactionsServer) error {

	var startBlock, endBlock *wallet.BlockIdentifier
	if req.StartingBlockHash != nil && req.StartingBlockHeight != 0 {
		return status.Errorf(codes.InvalidArgument,
			"starting block hash and height may not be specified simultaneously")
	} else if req.StartingBlockHash != nil {
		startBlockHash, err := chainhash.NewHash(req.StartingBlockHash)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "%s", err.Error())
		}
		startBlock = wallet.NewBlockIdentifierFromHash(startBlockHash)
	} else if req.StartingBlockHeight != 0 {
		startBlock = wallet.NewBlockIdentifierFromHeight(req.StartingBlockHeight)
	}

	if req.EndingBlockHash != nil && req.EndingBlockHeight != 0 {
		return status.Errorf(codes.InvalidArgument,
			"ending block hash and height may not be specified simultaneously")
	} else if req.EndingBlockHash != nil {
		endBlockHash, err := chainhash.NewHash(req.EndingBlockHash)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "%s", err.Error())
		}
		endBlock = wallet.NewBlockIdentifierFromHash(endBlockHash)
	} else if req.EndingBlockHeight != 0 {
		endBlock = wallet.NewBlockIdentifierFromHeight(req.EndingBlockHeight)
	}

	var minRecentTxs int
	if req.MinimumRecentTransactions != 0 {
		if endBlock != nil {
			return status.Errorf(codes.InvalidArgument,
				"ending block and minimum number of recent transactions "+
					"may not be specified simultaneously")
		}
		minRecentTxs = int(req.MinimumRecentTransactions)
		if minRecentTxs < 0 {
			return status.Errorf(codes.InvalidArgument,
				"minimum number of recent transactions may not be negative")
		}
	}
	_ = minRecentTxs

	targetTxCount := int(req.TargetTransactionCount)
	if targetTxCount < 0 {
		return status.Errorf(codes.InvalidArgument,
			"maximum transaction count may not be negative")
	}

	ctx := server.Context()
	txCount := 0

	rangeFn := func(block *wallet.Block) (bool, error) {
		var resp *pb.GetTransactionsResponse
		if block.Header != nil {
			resp = &pb.GetTransactionsResponse{
				MinedTransactions: marshalBlock(block),
			}
		} else {
			resp = &pb.GetTransactionsResponse{
				UnminedTransactions: marshalTransactionDetailsSlice(block.Transactions),
			}
		}
		txCount += len(block.Transactions)

		select {
		case <-ctx.Done():
			return true, ctx.Err()
		default:
			err := server.Send(resp)
			return (err != nil) || ((targetTxCount > 0) && (txCount >= targetTxCount)), err
		}
	}

	err := s.wallet.GetTransactions(rangeFn, startBlock, endBlock)
	if err != nil {
		return translateError(err)
	}

	return nil
}

func (s *walletServer) ChangePassphrase(ctx context.Context, req *pb.ChangePassphraseRequest) (
	*pb.ChangePassphraseResponse, error) {

	defer func() {
		zero.Bytes(req.OldPassphrase)
		zero.Bytes(req.NewPassphrase)
	}()

	var (
		oldPass = req.OldPassphrase
		newPass = req.NewPassphrase
	)

	var err error
	switch req.Key {
	case pb.ChangePassphraseRequest_PRIVATE:
		err = s.wallet.ChangePrivatePassphrase(oldPass, newPass)
	case pb.ChangePassphraseRequest_PUBLIC:
		if len(oldPass) == 0 {
			oldPass = []byte(wallet.InsecurePubPassphrase)
		}
		if len(newPass) == 0 {
			newPass = []byte(wallet.InsecurePubPassphrase)
		}
		err = s.wallet.ChangePublicPassphrase(oldPass, newPass)
	default:
		return nil, status.Errorf(codes.InvalidArgument, "Unknown key type (%d)", req.Key)
	}
	if err != nil {
		return nil, translateError(err)
	}
	return &pb.ChangePassphraseResponse{}, nil
}

func (s *walletServer) SignTransaction(ctx context.Context, req *pb.SignTransactionRequest) (
	*pb.SignTransactionResponse, error) {

	defer zero.Bytes(req.Passphrase)

	var tx wire.MsgTx
	err := tx.Deserialize(bytes.NewReader(req.SerializedTransaction))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument,
			"Bytes do not represent a valid raw transaction: %v", err)
	}

	lock := make(chan time.Time, 1)
	defer func() {
		lock <- time.Time{} // send matters, not the value
	}()
	err = s.wallet.Unlock(req.Passphrase, lock)
	if err != nil {
		return nil, translateError(err)
	}

	var additionalPkScripts map[wire.OutPoint][]byte
	if len(req.AdditionalScripts) > 0 {
		additionalPkScripts = make(map[wire.OutPoint][]byte, len(req.AdditionalScripts))
		for _, script := range req.AdditionalScripts {
			op := wire.OutPoint{Index: script.OutputIndex}
			if len(script.TransactionHash) != chainhash.HashSize {
				return nil, status.Errorf(codes.InvalidArgument,
					"Invalid transaction hash length for script %v, expected %v got %v",
					script, chainhash.HashSize, len(script.TransactionHash))
			}

			copy(op.Hash[:], script.TransactionHash)
			additionalPkScripts[op] = script.PkScript
		}
	}

	invalidSigs, err := s.wallet.SignTransaction(&tx, txscript.SigHashAll, additionalPkScripts, nil, nil)
	if err != nil {
		return nil, translateError(err)
	}

	invalidInputIndexes := make([]uint32, len(invalidSigs))
	for i, e := range invalidSigs {
		invalidInputIndexes[i] = e.InputIndex
	}

	var serializedTransaction bytes.Buffer
	serializedTransaction.Grow(tx.SerializeSize())
	err = tx.Serialize(&serializedTransaction)
	if err != nil {
		return nil, translateError(err)
	}

	resp := &pb.SignTransactionResponse{
		Transaction:          serializedTransaction.Bytes(),
		UnsignedInputIndexes: invalidInputIndexes,
	}
	return resp, nil
}

func (s *walletServer) SignTransactions(ctx context.Context, req *pb.SignTransactionsRequest) (
	*pb.SignTransactionsResponse, error) {
	defer zero.Bytes(req.Passphrase)

	lock := make(chan time.Time, 1)
	defer func() {
		lock <- time.Time{} // send matters, not the value
	}()
	err := s.wallet.Unlock(req.Passphrase, lock)
	if err != nil {
		return nil, translateError(err)
	}

	var additionalPkScripts map[wire.OutPoint][]byte
	if len(req.AdditionalScripts) > 0 {
		additionalPkScripts = make(map[wire.OutPoint][]byte, len(req.AdditionalScripts))
		for _, script := range req.AdditionalScripts {
			op := wire.OutPoint{Index: script.OutputIndex}
			if len(script.TransactionHash) != chainhash.HashSize {
				return nil, status.Errorf(codes.InvalidArgument,
					"Invalid transaction hash length for script %v, expected %v got %v",
					script, chainhash.HashSize, len(script.TransactionHash))
			}

			copy(op.Hash[:], script.TransactionHash)
			additionalPkScripts[op] = script.PkScript
		}
	}

	resp := pb.SignTransactionsResponse{}
	resp.Transactions = make([]*pb.SignTransactionsResponse_SignedTransaction, 0, len(req.Transactions))
	for _, unsignedTx := range req.Transactions {
		var tx wire.MsgTx
		err := tx.Deserialize(bytes.NewReader(unsignedTx.SerializedTransaction))
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument,
				"Bytes do not represent a valid raw transaction: %v", err)
		}

		invalidSigs, err := s.wallet.SignTransaction(&tx, txscript.SigHashAll, additionalPkScripts, nil, nil)
		if err != nil {
			return nil, translateError(err)
		}

		invalidInputIndexes := make([]uint32, len(invalidSigs))
		for i, e := range invalidSigs {
			invalidInputIndexes[i] = e.InputIndex
		}

		var serializedTransaction bytes.Buffer
		serializedTransaction.Grow(tx.SerializeSize())
		err = tx.Serialize(&serializedTransaction)
		if err != nil {
			return nil, translateError(err)
		}

		resp.Transactions = append(resp.Transactions, &pb.SignTransactionsResponse_SignedTransaction{
			Transaction:          serializedTransaction.Bytes(),
			UnsignedInputIndexes: invalidInputIndexes,
		})
	}

	return &resp, nil
}

func (s *walletServer) CreateSignature(ctx context.Context, req *pb.CreateSignatureRequest) (
	*pb.CreateSignatureResponse, error) {

	defer zero.Bytes(req.Passphrase)

	var tx wire.MsgTx
	err := tx.Deserialize(bytes.NewReader(req.SerializedTransaction))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument,
			"Bytes do not represent a valid raw transaction: %v", err)
	}

	if req.InputIndex >= uint32(len(tx.TxIn)) {
		return nil, status.Errorf(codes.InvalidArgument,
			"transaction input %d does not exist", req.InputIndex)
	}

	lock := make(chan time.Time, 1)
	defer func() {
		lock <- time.Time{} // send matters, not the value
	}()
	err = s.wallet.Unlock(req.Passphrase, lock)
	if err != nil {
		return nil, translateError(err)
	}

	addr, err := decodeAddress(req.Address, s.wallet.ChainParams())
	if err != nil {
		return nil, err
	}

	hashType := txscript.SigHashType(req.HashType)
	sig, pubkey, err := s.wallet.CreateSignature(&tx, req.InputIndex, addr, hashType, req.PreviousPkScript)
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.CreateSignatureResponse{Signature: sig, PublicKey: pubkey}, nil
}

func (s *walletServer) PublishTransaction(ctx context.Context, req *pb.PublishTransactionRequest) (
	*pb.PublishTransactionResponse, error) {

	n, err := s.requireNetworkBackend()
	if err != nil {
		return nil, err
	}

	var msgTx wire.MsgTx
	err = msgTx.Deserialize(bytes.NewReader(req.SignedTransaction))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument,
			"Bytes do not represent a valid raw transaction: %v", err)
	}

	txHash, err := s.wallet.PublishTransaction(&msgTx, req.SignedTransaction, n)
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.PublishTransactionResponse{TransactionHash: txHash[:]}, nil
}

func (s *walletServer) LoadActiveDataFilters(ctx context.Context, req *pb.LoadActiveDataFiltersRequest) (
	*pb.LoadActiveDataFiltersResponse, error) {

	n, err := s.requireNetworkBackend()
	if err != nil {
		return nil, err
	}

	err = s.wallet.LoadActiveDataFilters(ctx, n, false)
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.LoadActiveDataFiltersResponse{}, nil
}

func (s *walletServer) signMessage(address, message string) ([]byte, error) {
	addr, err := decodeAddress(address, s.wallet.ChainParams())
	if err != nil {
		return nil, err
	}

	// Addresses must have an associated secp256k1 private key and therefore
	// must be P2PK or P2PKH (P2SH is not allowed).
	var sig []byte
	switch a := addr.(type) {
	case *ndrutil.AddressSecpPubKey:
	case *ndrutil.AddressPubKeyHash:
		if a.DSA(a.Net()) != ndrec.STEcdsaSecp256k1 {
			goto WrongAddrKind
		}
	default:
		goto WrongAddrKind
	}

	sig, err = s.wallet.SignMessage(message, addr)
	if err != nil {
		return nil, translateError(err)
	}
	return sig, nil

WrongAddrKind:
	return nil, status.Error(codes.InvalidArgument,
		"address must be secp256k1 P2PK or P2PKH")
}

func (s *walletServer) SignMessage(cts context.Context, req *pb.SignMessageRequest) (*pb.SignMessageResponse, error) {
	lock := make(chan time.Time, 1)
	defer func() {
		lock <- time.Time{} // send matters, not the value
	}()
	err := s.wallet.Unlock(req.Passphrase, lock)
	if err != nil {
		return nil, translateError(err)
	}

	sig, err := s.signMessage(req.Address, req.Message)
	if err != nil {
		return nil, err
	}

	return &pb.SignMessageResponse{Signature: sig}, nil
}

func (s *walletServer) SignMessages(cts context.Context, req *pb.SignMessagesRequest) (*pb.SignMessagesResponse, error) {
	lock := make(chan time.Time, 1)
	defer func() {
		lock <- time.Time{} // send matters, not the value
	}()
	err := s.wallet.Unlock(req.Passphrase, lock)
	if err != nil {
		return nil, translateError(err)
	}

	smr := pb.SignMessagesResponse{
		Replies: make([]*pb.SignMessagesResponse_SignReply, 0,
			len(req.Messages)),
	}
	for _, v := range req.Messages {
		e := ""
		sig, err := s.signMessage(v.Address, v.Message)
		if err != nil {
			e = err.Error()
		}
		smr.Replies = append(smr.Replies,
			&pb.SignMessagesResponse_SignReply{
				Signature: sig,
				Error:     e,
			})
	}

	return &smr, nil
}

func (s *walletServer) ValidateAddress(ctx context.Context, req *pb.ValidateAddressRequest) (*pb.ValidateAddressResponse, error) {
	result := &pb.ValidateAddressResponse{}
	addr, err := decodeAddress(req.GetAddress(), s.wallet.ChainParams())
	if err != nil {
		return result, nil
	}

	result.IsValid = true
	addrInfo, err := s.wallet.AddressInfo(addr)
	if err != nil {
		if errors.Is(errors.NotExist, err) {
			// No additional information available about the address.
			return result, nil
		}
		return nil, err
	}

	// The address lookup was successful which means there is further
	// information about it available and it is "mine".
	result.IsMine = true
	acctName, err := s.wallet.AccountName(addrInfo.Account())
	if err != nil {
		return nil, translateError(err)
	}

	acctNumber, err := s.wallet.AccountNumber(acctName)
	if err != nil {
		return nil, err
	}
	result.AccountNumber = acctNumber

	switch ma := addrInfo.(type) {
	case udb.ManagedPubKeyAddress:
		result.PubKey = ma.PubKey().Serialize()
		pubKeyAddr, err := ndrutil.NewAddressSecpPubKey(result.PubKey,
			s.wallet.ChainParams())
		if err != nil {
			return nil, err
		}
		result.PubKeyAddr = pubKeyAddr.String()
		result.IsInternal = ma.Internal()
		result.Index = ma.Index()

	case udb.ManagedScriptAddress:
		result.IsScript = true

		// The script is only available if the manager is unlocked, so
		// just break out now if there is an error.
		script, err := s.wallet.RedeemScriptCopy(addr)
		if err != nil {
			break
		}
		result.PayToAddrScript = script

		// This typically shouldn't fail unless an invalid script was
		// imported.  However, if it fails for any reason, there is no
		// further information available, so just set the script type
		// a non-standard and break out now.
		class, addrs, reqSigs, err := txscript.ExtractPkScriptAddrs(
			txscript.DefaultScriptVersion, script, s.wallet.ChainParams())
		if err != nil {
			result.ScriptType = pb.ValidateAddressResponse_NonStandardTy
			break
		}

		addrStrings := make([]string, len(addrs))
		for i, a := range addrs {
			addrStrings[i] = a.EncodeAddress()
		}
		result.PkScriptAddrs = addrStrings

		// Multi-signature scripts also provide the number of required
		// signatures.
		result.ScriptType = pb.ValidateAddressResponse_ScriptType(uint32(class))
		if class == txscript.MultiSigTy {
			result.SigsRequired = uint32(reqSigs)
		}
	}

	return result, nil
}

func marshalTransactionInputs(v []wallet.TransactionSummaryInput) []*pb.TransactionDetails_Input {
	inputs := make([]*pb.TransactionDetails_Input, len(v))
	for i := range v {
		input := &v[i]
		inputs[i] = &pb.TransactionDetails_Input{
			Index:           input.Index,
			PreviousAccount: input.PreviousAccount,
			PreviousAmount:  int64(input.PreviousAmount),
		}
	}
	return inputs
}

func marshalTransactionOutputs(v []wallet.TransactionSummaryOutput) []*pb.TransactionDetails_Output {
	outputs := make([]*pb.TransactionDetails_Output, len(v))
	for i := range v {
		output := &v[i]
		address := ""
		if output.Address != nil {
			address = output.Address.String()
		}
		outputs[i] = &pb.TransactionDetails_Output{
			Index:        output.Index,
			Account:      output.Account,
			Internal:     output.Internal,
			Amount:       int64(output.Amount),
			Address:      address,
			OutputScript: output.OutputScript,
		}
	}
	return outputs
}

func marshalTxType(walletTxType wallet.TransactionType) pb.TransactionDetails_TransactionType {
	switch walletTxType {
	case wallet.TransactionTypeCoinbase:
		return pb.TransactionDetails_COINBASE
	default:
		return pb.TransactionDetails_REGULAR
	}
}

func marshalTransactionDetails(tx *wallet.TransactionSummary) *pb.TransactionDetails {

	return &pb.TransactionDetails{
		Hash:            tx.Hash[:],
		Transaction:     tx.Transaction,
		Debits:          marshalTransactionInputs(tx.MyInputs),
		Credits:         marshalTransactionOutputs(tx.MyOutputs),
		Fee:             int64(tx.Fee),
		Timestamp:       tx.Timestamp,
		TransactionType: marshalTxType(tx.Type),
	}
}

func marshalTransactionDetailsSlice(v []wallet.TransactionSummary) []*pb.TransactionDetails {
	txs := make([]*pb.TransactionDetails, len(v))
	for i := range v {
		txs[i] = marshalTransactionDetails(&v[i])
	}
	return txs
}

func marshalBlock(v *wallet.Block) *pb.BlockDetails {
	txs := marshalTransactionDetailsSlice(v.Transactions)

	if v.Header == nil {
		return &pb.BlockDetails{
			Hash:         nil,
			Height:       -1,
			Transactions: txs,
		}
	}

	hash := v.Header.BlockHash()
	return &pb.BlockDetails{
		Hash:         hash[:],
		Height:       int32(v.Header.Height),
		Timestamp:    v.Header.Timestamp.Unix(),
		Transactions: txs,
	}
}

func marshalBlocks(v []wallet.Block) []*pb.BlockDetails {
	blocks := make([]*pb.BlockDetails, len(v))
	for i := range v {
		blocks[i] = marshalBlock(&v[i])
	}
	return blocks
}

func marshalHashes(v []*chainhash.Hash) [][]byte {
	hashes := make([][]byte, len(v))
	for i, hash := range v {
		hashes[i] = hash[:]
	}
	return hashes
}

func (s *walletServer) TransactionNotifications(req *pb.TransactionNotificationsRequest,
	svr pb.WalletService_TransactionNotificationsServer) error {

	n := s.wallet.NtfnServer.TransactionNotifications()
	defer n.Done()

	ctxDone := svr.Context().Done()
	for {
		select {
		case v := <-n.C:
			resp := pb.TransactionNotificationsResponse{
				AttachedBlocks:           marshalBlocks(v.AttachedBlocks),
				DetachedBlocks:           marshalHashes(v.DetachedBlocks),
				UnminedTransactions:      marshalTransactionDetailsSlice(v.UnminedTransactions),
				UnminedTransactionHashes: marshalHashes(v.UnminedTransactionHashes),
			}
			err := svr.Send(&resp)
			if err != nil {
				return translateError(err)
			}

		case <-ctxDone:
			return nil
		}
	}
}

func (s *walletServer) AccountNotifications(req *pb.AccountNotificationsRequest,
	svr pb.WalletService_AccountNotificationsServer) error {

	n := s.wallet.NtfnServer.AccountNotifications()
	defer n.Done()

	ctxDone := svr.Context().Done()
	for {
		select {
		case v := <-n.C:
			resp := pb.AccountNotificationsResponse{
				AccountNumber:    v.AccountNumber,
				AccountName:      v.AccountName,
				ExternalKeyCount: v.ExternalKeyCount,
				InternalKeyCount: v.InternalKeyCount,
				ImportedKeyCount: v.ImportedKeyCount,
			}
			err := svr.Send(&resp)
			if err != nil {
				return translateError(err)
			}

		case <-ctxDone:
			return nil
		}
	}
}

func (s *walletServer) ConfirmationNotifications(svr pb.WalletService_ConfirmationNotificationsServer) error {
	c := s.wallet.NtfnServer.ConfirmationNotifications(svr.Context())
	errOut := make(chan error, 2)
	go func() {
		for {
			req, err := svr.Recv()
			if err != nil {
				errOut <- err
				return
			}
			txHashes, err := decodeHashes(req.TxHashes)
			if err != nil {
				errOut <- err
				return
			}
			if req.StopAfter < 0 {
				errOut <- status.Errorf(codes.InvalidArgument, "stop_after must be non-negative")
				return
			}
			c.Watch(txHashes, req.StopAfter)
		}
	}()
	go func() {
		for {
			n, err := c.Recv()
			if err != nil {
				errOut <- err
				return
			}
			results := make([]*pb.ConfirmationNotificationsResponse_TransactionConfirmations, len(n))
			for i, r := range n {
				var blockHash []byte
				if r.BlockHash != nil {
					blockHash = r.BlockHash[:]
				}
				results[i] = &pb.ConfirmationNotificationsResponse_TransactionConfirmations{
					TxHash:        r.TxHash[:],
					Confirmations: r.Confirmations,
					BlockHash:     blockHash,
					BlockHeight:   r.BlockHeight,
				}
			}
			r := &pb.ConfirmationNotificationsResponse{
				Confirmations: results,
			}
			err = svr.Send(r)
			if err != nil {
				errOut <- err
				return
			}
		}
	}()

	select {
	case <-svr.Context().Done():
		return nil
	case err := <-errOut:
		if err == context.Canceled {
			return nil
		}
		if _, ok := status.FromError(err); ok {
			return err
		}
		return translateError(err)
	}
}

// StartWalletLoaderService starts the WalletLoaderService.
func StartWalletLoaderService(server *grpc.Server, loader *loader.Loader, activeNet *netparams.Params) {
	loaderService.loader = loader
	loaderService.activeNet = activeNet
	if atomic.SwapUint32(&loaderService.ready, 1) != 0 {
		panic("service already started")
	}
}

func (s *loaderServer) checkReady() bool {
	return atomic.LoadUint32(&s.ready) != 0
}

func (s *loaderServer) CreateWallet(ctx context.Context, req *pb.CreateWalletRequest) (
	*pb.CreateWalletResponse, error) {

	defer func() {
		zero.Bytes(req.PrivatePassphrase)
		zero.Bytes(req.Seed)
	}()

	// Use an insecure public passphrase when the request's is empty.
	pubPassphrase := req.PublicPassphrase
	if len(pubPassphrase) == 0 {
		pubPassphrase = []byte(wallet.InsecurePubPassphrase)
	}

	// Seed is required.
	if len(req.Seed) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "seed is a required parameter")
	}

	_, err := s.loader.CreateNewWallet(pubPassphrase, req.PrivatePassphrase, req.Seed)
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.CreateWalletResponse{}, nil
}

func (s *loaderServer) CreateWatchingOnlyWallet(ctx context.Context, req *pb.CreateWatchingOnlyWalletRequest) (
	*pb.CreateWatchingOnlyWalletResponse, error) {

	// Use an insecure public passphrase when the request's is empty.
	pubPassphrase := req.PublicPassphrase
	if len(pubPassphrase) == 0 {
		pubPassphrase = []byte(wallet.InsecurePubPassphrase)
	}

	_, err := s.loader.CreateWatchingOnlyWallet(req.ExtendedPubKey, pubPassphrase)
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.CreateWatchingOnlyWalletResponse{}, nil
}

func (s *loaderServer) OpenWallet(ctx context.Context, req *pb.OpenWalletRequest) (
	*pb.OpenWalletResponse, error) {

	// Use an insecure public passphrase when the request's is empty.
	pubPassphrase := req.PublicPassphrase
	if len(pubPassphrase) == 0 {
		pubPassphrase = []byte(wallet.InsecurePubPassphrase)
	}

	w, err := s.loader.OpenExistingWallet(pubPassphrase)
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.OpenWalletResponse{
		WatchingOnly: w.Manager.WatchingOnly(),
	}, nil
}

func (s *loaderServer) WalletExists(ctx context.Context, req *pb.WalletExistsRequest) (
	*pb.WalletExistsResponse, error) {

	exists, err := s.loader.WalletExists()
	if err != nil {
		return nil, translateError(err)
	}
	return &pb.WalletExistsResponse{Exists: exists}, nil
}

func (s *loaderServer) CloseWallet(ctx context.Context, req *pb.CloseWalletRequest) (
	*pb.CloseWalletResponse, error) {

	err := s.loader.UnloadWallet()
	if errors.Is(errors.Invalid, err) {
		return nil, status.Errorf(codes.FailedPrecondition, "Wallet is not loaded")
	}
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.CloseWalletResponse{}, nil
}

func (s *loaderServer) StartConsensusRpc(ctx context.Context, req *pb.StartConsensusRpcRequest) (
	*pb.StartConsensusRpcResponse, error) {

	defer zero.Bytes(req.Password)

	defer s.mu.Unlock()
	s.mu.Lock()

	if s.rpcClient != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "RPC client already created")
	}

	networkAddress, err := cfgutil.NormalizeAddress(req.NetworkAddress,
		s.activeNet.JSONRPCClientPort)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument,
			"Network address is ill-formed: %v", err)
	}

	// Error if the wallet is already syncing with the network.
	wallet, walletLoaded := s.loader.LoadedWallet()
	if walletLoaded {
		_, err := wallet.NetworkBackend()
		if err == nil {
			return nil, status.Errorf(codes.FailedPrecondition,
				"wallet is loaded and already synchronizing")
		}
	}

	rpcClient, err := chain.NewRPCClient(s.activeNet.Params, networkAddress, req.Username,
		string(req.Password), req.Certificate, len(req.Certificate) == 0)
	if err != nil {
		return nil, translateError(err)
	}

	err = rpcClient.Start(ctx, false)
	if err != nil {
		if err == rpcclient.ErrInvalidAuth {
			return nil, status.Errorf(codes.InvalidArgument,
				"Invalid RPC credentials: %v", err)
		}
		return nil, status.Errorf(codes.NotFound,
			"Connection to RPC server failed: %v", err)
	}

	s.rpcClient = rpcClient
	s.loader.SetNetworkBackend(chain.BackendFromRPCClient(rpcClient.Client))

	return &pb.StartConsensusRpcResponse{}, nil
}

func (s *loaderServer) DiscoverAddresses(ctx context.Context, req *pb.DiscoverAddressesRequest) (
	*pb.DiscoverAddressesResponse, error) {

	wallet, ok := s.loader.LoadedWallet()
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "Wallet has not been loaded")
	}

	s.mu.Lock()
	chainClient := s.rpcClient
	s.mu.Unlock()
	if chainClient == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "Consensus server RPC client has not been loaded")
	}

	if req.DiscoverAccounts && len(req.PrivatePassphrase) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "private passphrase is required for discovering accounts")
	}

	if req.DiscoverAccounts {
		lock := make(chan time.Time, 1)
		defer func() {
			lock <- time.Time{}
			zero.Bytes(req.PrivatePassphrase)
		}()
		err := wallet.Unlock(req.PrivatePassphrase, lock)
		if err != nil {
			return nil, translateError(err)
		}
	}
	n := chain.BackendFromRPCClient(chainClient.Client)
	startHash := wallet.ChainParams().GenesisHash
	var err error
	if req.StartingBlockHash != nil {
		startHash, err = chainhash.NewHash(req.StartingBlockHash)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "Invalid starting block hash provided: %v", err)
		}
	}
	err = wallet.DiscoverActiveAddresses(ctx, n, startHash, req.DiscoverAccounts)
	if err != nil {
		return nil, translateError(err)
	}

	return &pb.DiscoverAddressesResponse{}, nil
}

func (s *loaderServer) FetchMissingCFilters(ctx context.Context, req *pb.FetchMissingCFiltersRequest) (
	*pb.FetchMissingCFiltersResponse, error) {

	wallet, ok := s.loader.LoadedWallet()
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "Wallet has not been loaded")
	}

	n := chain.BackendFromRPCClient(s.rpcClient.Client)
	// Fetch any missing main chain compact filters.
	err := wallet.FetchMissingCFilters(ctx, n)
	if err != nil {
		return nil, err
	}

	return &pb.FetchMissingCFiltersResponse{}, nil
}

func (s *loaderServer) RpcSync(req *pb.RpcSyncRequest, svr pb.WalletLoaderService_RpcSyncServer) error {
	defer zero.Bytes(req.Password)

	// Error if the wallet is already syncing with the network.
	wallet, walletLoaded := s.loader.LoadedWallet()
	if walletLoaded {
		_, err := wallet.NetworkBackend()
		if err == nil {
			return status.Errorf(codes.FailedPrecondition, "wallet is loaded and already synchronizing")
		}
	}

	if req.DiscoverAccounts && len(req.PrivatePassphrase) == 0 {
		return status.Errorf(codes.InvalidArgument, "private passphrase is required for discovering accounts")
	}
	var lockWallet func()
	if req.DiscoverAccounts {
		lock := make(chan time.Time, 1)
		lockWallet = func() {
			lock <- time.Time{}
			zero.Bytes(req.PrivatePassphrase)
		}
		defer lockWallet()
		err := wallet.Unlock(req.PrivatePassphrase, lock)
		if err != nil {
			return translateError(err)
		}
	}

	s.mu.Lock()
	chainClient := s.rpcClient
	s.mu.Unlock()

	// If the rpcClient is already set, you can just use that instead of attempting a new connection.
	if chainClient == nil {
		networkAddress, err := cfgutil.NormalizeAddress(req.NetworkAddress,
			s.activeNet.JSONRPCClientPort)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "Network address is ill-formed: %v", err)
		}
		chainClient, err = chain.NewRPCClient(s.activeNet.Params, networkAddress, req.Username,
			string(req.Password), req.Certificate, len(req.Certificate) == 0)
		if err != nil {
			return translateError(err)
		}

		err = chainClient.Start(svr.Context(), false)
		if err != nil {
			if err == rpcclient.ErrInvalidAuth {
				return status.Errorf(codes.InvalidArgument, "Invalid RPC credentials: %v", err)
			}
			if errors.Match(errors.E(context.Canceled), err) {
				return status.Errorf(codes.Canceled, "Wallet synchronization canceled: %v", err)
			}
			return status.Errorf(codes.Unavailable, "Connection to RPC server failed: %v", err)
		}
		s.mu.Lock()
		s.rpcClient = chainClient
		s.mu.Unlock()
	}

	n := chain.BackendFromRPCClient(chainClient.Client)
	s.loader.SetNetworkBackend(n)
	wallet.SetNetworkBackend(n)

	// Disassociate the RPC client from all subsystems until reconnection
	// occurs.
	defer wallet.SetNetworkBackend(nil)
	defer s.loader.SetNetworkBackend(nil)

	ntfns := &chain.Notifications{
		Synced: func(sync bool) {
			resp := &pb.RpcSyncResponse{}
			resp.Synced = sync
			if sync {
				resp.NotificationType = pb.SyncNotificationType_SYNCED
			} else {
				resp.NotificationType = pb.SyncNotificationType_UNSYNCED
			}
			_ = svr.Send(resp)
		},
		FetchMissingCFiltersStarted: func() {
			resp := &pb.RpcSyncResponse{
				NotificationType: pb.SyncNotificationType_FETCHED_MISSING_CFILTERS_STARTED,
			}
			_ = svr.Send(resp)
		},
		FetchMissingCFiltersProgress: func(missingCFitlersStart, missingCFitlersEnd int32) {
			resp := &pb.RpcSyncResponse{
				NotificationType: pb.SyncNotificationType_FETCHED_MISSING_CFILTERS_PROGRESS,
				FetchMissingCfilters: &pb.FetchMissingCFiltersNotification{
					FetchedCfiltersStartHeight: missingCFitlersStart,
					FetchedCfiltersEndHeight:   missingCFitlersEnd,
				},
			}
			_ = svr.Send(resp)
		},
		FetchMissingCFiltersFinished: func() {
			resp := &pb.RpcSyncResponse{
				NotificationType: pb.SyncNotificationType_FETCHED_MISSING_CFILTERS_FINISHED,
			}
			_ = svr.Send(resp)
		},
		FetchHeadersStarted: func() {
			resp := &pb.RpcSyncResponse{
				NotificationType: pb.SyncNotificationType_FETCHED_HEADERS_STARTED,
			}
			_ = svr.Send(resp)
		},
		FetchHeadersProgress: func(fetchedHeadersCount int32, lastHeaderTime int64) {
			resp := &pb.RpcSyncResponse{
				NotificationType: pb.SyncNotificationType_FETCHED_HEADERS_PROGRESS,
				FetchHeaders: &pb.FetchHeadersNotification{
					FetchedHeadersCount: fetchedHeadersCount,
					LastHeaderTime:      lastHeaderTime,
				},
			}
			_ = svr.Send(resp)
		},
		FetchHeadersFinished: func() {
			resp := &pb.RpcSyncResponse{
				NotificationType: pb.SyncNotificationType_FETCHED_HEADERS_FINISHED,
			}
			_ = svr.Send(resp)
		},
		DiscoverAddressesStarted: func() {
			resp := &pb.RpcSyncResponse{
				NotificationType: pb.SyncNotificationType_DISCOVER_ADDRESSES_STARTED,
			}
			_ = svr.Send(resp)
		},
		DiscoverAddressesFinished: func() {
			resp := &pb.RpcSyncResponse{
				NotificationType: pb.SyncNotificationType_DISCOVER_ADDRESSES_FINISHED,
			}

			// Lock the wallet after the first time discovered while also
			// discovering accounts.
			if lockWallet != nil {
				lockWallet()
				lockWallet = nil
			}
			_ = svr.Send(resp)
		},
		RescanStarted: func() {
			resp := &pb.RpcSyncResponse{
				NotificationType: pb.SyncNotificationType_RESCAN_STARTED,
			}
			_ = svr.Send(resp)
		},
		RescanProgress: func(rescannedThrough int32) {
			resp := &pb.RpcSyncResponse{
				NotificationType: pb.SyncNotificationType_RESCAN_PROGRESS,
				RescanProgress: &pb.RescanProgressNotification{
					RescannedThrough: rescannedThrough,
				},
			}
			_ = svr.Send(resp)
		},
		RescanFinished: func() {
			resp := &pb.RpcSyncResponse{
				NotificationType: pb.SyncNotificationType_RESCAN_FINISHED,
			}
			_ = svr.Send(resp)
		},
	}
	syncer := chain.NewRPCSyncer(wallet, chainClient)
	syncer.SetNotifications(ntfns)

	// Run wallet synchronization until it is cancelled or errors.  If the
	// context was cancelled, return immediately instead of trying to
	// reconnect.
	err := syncer.Run(svr.Context(), true)
	if err != nil {
		if svr.Context().Err() != nil {
			return status.Errorf(codes.Canceled, "Wallet synchronization canceled: %v", err)
		}
		return status.Errorf(codes.Unknown, "Wallet synchronization stopped: %v", err)
	}

	return nil
}

func (s *loaderServer) SpvSync(req *pb.SpvSyncRequest, svr pb.WalletLoaderService_SpvSyncServer) error {
	wallet, ok := s.loader.LoadedWallet()
	if !ok {
		return status.Errorf(codes.FailedPrecondition, "Wallet has not been loaded")
	}

	if req.DiscoverAccounts && len(req.PrivatePassphrase) == 0 {
		return status.Errorf(codes.InvalidArgument, "private passphrase is required for discovering accounts")
	}
	var lockWallet func()
	if req.DiscoverAccounts {
		lock := make(chan time.Time, 1)
		lockWallet = func() {
			lock <- time.Time{}
			zero.Bytes(req.PrivatePassphrase)
		}
		defer lockWallet()
		err := wallet.Unlock(req.PrivatePassphrase, lock)
		if err != nil {
			return translateError(err)
		}
	}
	addr := &net.TCPAddr{IP: net.ParseIP("::1"), Port: 0}
	amgr := addrmgr.New(s.loader.DbDirPath(), net.LookupIP) // TODO: be mindful of tor
	lp := p2p.NewLocalPeer(wallet.ChainParams(), addr, amgr)

	ntfns := &spv.Notifications{
		Synced: func(sync bool) {
			resp := &pb.SpvSyncResponse{}
			resp.Synced = sync
			if sync {
				resp.NotificationType = pb.SyncNotificationType_SYNCED
			} else {
				resp.NotificationType = pb.SyncNotificationType_UNSYNCED
			}
			_ = svr.Send(resp)
		},
		PeerConnected: func(peerCount int32, addr string) {
			resp := &pb.SpvSyncResponse{
				NotificationType: pb.SyncNotificationType_PEER_CONNECTED,
				PeerInformation: &pb.PeerNotification{
					PeerCount: peerCount,
					Address:   addr,
				},
			}
			_ = svr.Send(resp)
		},
		PeerDisconnected: func(peerCount int32, addr string) {
			resp := &pb.SpvSyncResponse{
				NotificationType: pb.SyncNotificationType_PEER_DISCONNECTED,
				PeerInformation: &pb.PeerNotification{
					PeerCount: peerCount,
					Address:   addr,
				},
			}
			_ = svr.Send(resp)
		},
		FetchMissingCFiltersStarted: func() {
			resp := &pb.SpvSyncResponse{
				NotificationType: pb.SyncNotificationType_FETCHED_MISSING_CFILTERS_STARTED,
			}
			_ = svr.Send(resp)
		},
		FetchMissingCFiltersProgress: func(missingCFitlersStart, missingCFitlersEnd int32) {
			resp := &pb.SpvSyncResponse{
				NotificationType: pb.SyncNotificationType_FETCHED_MISSING_CFILTERS_PROGRESS,
				FetchMissingCfilters: &pb.FetchMissingCFiltersNotification{
					FetchedCfiltersStartHeight: missingCFitlersStart,
					FetchedCfiltersEndHeight:   missingCFitlersEnd,
				},
			}
			_ = svr.Send(resp)
		},
		FetchMissingCFiltersFinished: func() {
			resp := &pb.SpvSyncResponse{
				NotificationType: pb.SyncNotificationType_FETCHED_MISSING_CFILTERS_FINISHED,
			}
			_ = svr.Send(resp)
		},
		FetchHeadersStarted: func() {
			resp := &pb.SpvSyncResponse{
				NotificationType: pb.SyncNotificationType_FETCHED_HEADERS_STARTED,
			}
			_ = svr.Send(resp)
		},
		FetchHeadersProgress: func(fetchedHeadersCount int32, lastHeaderTime int64) {
			resp := &pb.SpvSyncResponse{
				NotificationType: pb.SyncNotificationType_FETCHED_HEADERS_PROGRESS,
				FetchHeaders: &pb.FetchHeadersNotification{
					FetchedHeadersCount: fetchedHeadersCount,
					LastHeaderTime:      lastHeaderTime,
				},
			}
			_ = svr.Send(resp)
		},
		FetchHeadersFinished: func() {
			resp := &pb.SpvSyncResponse{
				NotificationType: pb.SyncNotificationType_FETCHED_HEADERS_FINISHED,
			}
			_ = svr.Send(resp)
		},
		DiscoverAddressesStarted: func() {
			resp := &pb.SpvSyncResponse{
				NotificationType: pb.SyncNotificationType_DISCOVER_ADDRESSES_STARTED,
			}
			_ = svr.Send(resp)
		},
		DiscoverAddressesFinished: func() {
			resp := &pb.SpvSyncResponse{
				NotificationType: pb.SyncNotificationType_DISCOVER_ADDRESSES_FINISHED,
			}

			// Lock the wallet after the first time discovered while also
			// discovering accounts.
			if lockWallet != nil {
				lockWallet()
				lockWallet = nil
			}
			_ = svr.Send(resp)
		},
		RescanStarted: func() {
			resp := &pb.SpvSyncResponse{
				NotificationType: pb.SyncNotificationType_RESCAN_STARTED,
			}
			_ = svr.Send(resp)
		},
		RescanProgress: func(rescannedThrough int32) {
			resp := &pb.SpvSyncResponse{
				NotificationType: pb.SyncNotificationType_RESCAN_PROGRESS,
				RescanProgress: &pb.RescanProgressNotification{
					RescannedThrough: rescannedThrough,
				},
			}
			_ = svr.Send(resp)
		},
		RescanFinished: func() {
			resp := &pb.SpvSyncResponse{
				NotificationType: pb.SyncNotificationType_RESCAN_FINISHED,
			}
			_ = svr.Send(resp)
		},
	}
	syncer := spv.NewSyncer(wallet, lp)
	syncer.SetNotifications(ntfns)
	if len(req.SpvConnect) > 0 {
		spvConnects := make([]string, len(req.SpvConnect))
		for i := 0; i < len(req.SpvConnect); i++ {
			spvConnect, err := cfgutil.NormalizeAddress(req.SpvConnect[i], s.activeNet.Params.DefaultPort)
			if err != nil {
				return status.Errorf(codes.FailedPrecondition, "SPV Connect address invalid: %v", err)
			}
			spvConnects[i] = spvConnect
		}
		syncer.SetPersistantPeers(spvConnects)
	}

	wallet.SetNetworkBackend(syncer)
	s.loader.SetNetworkBackend(syncer)

	defer wallet.SetNetworkBackend(nil)
	defer s.loader.SetNetworkBackend(nil)

	err := syncer.Run(svr.Context())
	if err != nil {
		if err == context.Canceled {
			return status.Errorf(codes.Canceled, "SPV synchronization canceled: %v", err)
		} else if err == context.DeadlineExceeded {
			return status.Errorf(codes.DeadlineExceeded, "SPV synchronization deadline exceeded: %v", err)
		}
		return translateError(err)
	}
	return nil
}

func (s *loaderServer) RescanPoint(ctx context.Context, req *pb.RescanPointRequest) (*pb.RescanPointResponse, error) {
	wallet, ok := s.loader.LoadedWallet()
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "Wallet has not been loaded")
	}
	rescanPoint, err := wallet.RescanPoint()
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "Rescan point failed to be requested %v", err)
	}
	if rescanPoint != nil {
		return &pb.RescanPointResponse{
			RescanPointHash: rescanPoint[:],
		}, nil
	}
	return &pb.RescanPointResponse{RescanPointHash: nil}, nil
}

func (s *loaderServer) SubscribeToBlockNotifications(ctx context.Context, req *pb.SubscribeToBlockNotificationsRequest) (
	*pb.SubscribeToBlockNotificationsResponse, error) {

	wallet, ok := s.loader.LoadedWallet()
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "Wallet has not been loaded")
	}

	s.mu.Lock()
	chainClient := s.rpcClient
	s.mu.Unlock()
	if chainClient == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "Consensus server RPC client has not been loaded")
	}

	err := chainClient.NotifyBlocks()
	if err != nil {
		return nil, translateError(err)
	}

	// TODO: instead of running the syncer in the background indefinitely,
	// deprecate this RPC and introduce two new RPCs, one to subscribe to the
	// notifications and one to perform the synchronization task.  This would be
	// a backwards-compatible way to improve error handling and provide more
	// control over how long the synchronization task runs.
	syncer := chain.NewRPCSyncer(wallet, chainClient)
	go syncer.Run(context.Background(), false)
	wallet.SetNetworkBackend(chain.BackendFromRPCClient(chainClient.Client))

	return &pb.SubscribeToBlockNotificationsResponse{}, nil
}

func (s *loaderServer) FetchHeaders(ctx context.Context, req *pb.FetchHeadersRequest) (
	*pb.FetchHeadersResponse, error) {

	wallet, ok := s.loader.LoadedWallet()
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "Wallet has not been loaded")
	}

	s.mu.Lock()
	chainClient := s.rpcClient
	s.mu.Unlock()
	if chainClient == nil {
		return nil, status.Errorf(codes.FailedPrecondition, "Consensus server RPC client has not been loaded")
	}
	n := chain.BackendFromRPCClient(chainClient.Client)

	fetchedHeaderCount, rescanFrom, rescanFromHeight,
		mainChainTipBlockHash, mainChainTipBlockHeight, err := wallet.FetchHeaders(ctx, n)
	if err != nil {
		return nil, translateError(err)
	}

	res := &pb.FetchHeadersResponse{
		FetchedHeadersCount:     uint32(fetchedHeaderCount),
		MainChainTipBlockHash:   mainChainTipBlockHash[:],
		MainChainTipBlockHeight: mainChainTipBlockHeight,
	}
	if fetchedHeaderCount > 0 {
		res.FirstNewBlockHash = rescanFrom[:]
		res.FirstNewBlockHeight = rescanFromHeight
	}
	return res, nil
}

func (s *seedServer) GenerateRandomSeed(ctx context.Context, req *pb.GenerateRandomSeedRequest) (
	*pb.GenerateRandomSeedResponse, error) {

	seedSize := req.SeedLength
	if seedSize == 0 {
		seedSize = hdkeychain.RecommendedSeedLen
	}
	if seedSize < hdkeychain.MinSeedBytes || seedSize > hdkeychain.MaxSeedBytes {
		return nil, status.Errorf(codes.InvalidArgument, "invalid seed length")
	}

	seed := make([]byte, seedSize)
	_, err := rand.Read(seed)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to read cryptographically-random data for seed: %v", err)
	}

	res := &pb.GenerateRandomSeedResponse{
		SeedBytes:    seed,
		SeedHex:      hex.EncodeToString(seed),
		SeedMnemonic: walletseed.EncodeMnemonic(seed),
	}
	return res, nil
}

func (s *seedServer) DecodeSeed(ctx context.Context, req *pb.DecodeSeedRequest) (*pb.DecodeSeedResponse, error) {
	seed, err := walletseed.DecodeUserInput(req.UserInput)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &pb.DecodeSeedResponse{DecodedSeed: seed}, nil
}

func (s *messageVerificationServer) VerifyMessage(ctx context.Context, req *pb.VerifyMessageRequest) (
	*pb.VerifyMessageResponse, error) {

	var valid bool

	addr, err := ndrutil.DecodeAddress(req.Address)
	if err != nil {
		return nil, translateError(err)
	}

	// Addresses must have an associated secp256k1 private key and therefore
	// must be P2PK or P2PKH (P2SH is not allowed).
	switch a := addr.(type) {
	case *ndrutil.AddressSecpPubKey:
	case *ndrutil.AddressPubKeyHash:
		if a.DSA(a.Net()) != ndrec.STEcdsaSecp256k1 {
			goto WrongAddrKind
		}
	default:
		goto WrongAddrKind
	}

	valid, err = wallet.VerifyMessage(req.Message, addr, req.Signature)
	if err != nil {
		return nil, translateError(err)
	}
	return &pb.VerifyMessageResponse{Valid: valid}, nil

WrongAddrKind:
	return nil, status.Error(codes.InvalidArgument, "address must be secp256k1 P2PK or P2PKH")
}

// StartDecodeMessageService starts the MessageDecode service
func StartDecodeMessageService(server *grpc.Server, chainParams *chaincfg.Params) {
	decodeMessageService.chainParams = chainParams
}

func marshalDecodedTxInputs(mtx *wire.MsgTx) []*pb.DecodedTransaction_Input {
	inputs := make([]*pb.DecodedTransaction_Input, len(mtx.TxIn))

	for i, txIn := range mtx.TxIn {
		// The disassembled string will contain [error] inline
		// if the script doesn't fully parse, so ignore the
		// error here.
		disbuf, _ := txscript.DisasmString(txIn.SignatureScript)

		inputs[i] = &pb.DecodedTransaction_Input{
			PreviousTransactionHash:  txIn.PreviousOutPoint.Hash[:],
			PreviousTransactionIndex: txIn.PreviousOutPoint.Index,
			Sequence:                 txIn.Sequence,
			AmountIn:                 txIn.ValueIn,
			BlockHeight:              txIn.BlockHeight,
			BlockIndex:               txIn.BlockIndex,
			SignatureScript:          txIn.SignatureScript,
			SignatureScriptAsm:       disbuf,
		}
	}

	return inputs
}

func marshalDecodedTxOutputs(mtx *wire.MsgTx, chainParams *chaincfg.Params) []*pb.DecodedTransaction_Output {
	outputs := make([]*pb.DecodedTransaction_Output, len(mtx.TxOut))

	for i, v := range mtx.TxOut {
		// The disassembled string will contain [error] inline if the
		// script doesn't fully parse, so ignore the error here.
		disbuf, _ := txscript.DisasmString(v.PkScript)

		// Attempt to extract addresses from the public key script.  In
		// the case of stake submission transactions, the odd outputs
		// contain a commitment address, so detect that case
		// accordingly.
		var addrs []ndrutil.Address
		var encodedAddrs []string
		var scriptClass txscript.ScriptClass
		var reqSigs int
		var commitAmt *ndrutil.Amount

		// Ignore the error here since an error means the script
		// couldn't parse and there is no additional information
		// about it anyways.
		scriptClass, addrs, reqSigs, _ = txscript.ExtractPkScriptAddrs(
			v.Version, v.PkScript, chainParams)
		encodedAddrs = make([]string, len(addrs))
		for j, addr := range addrs {
			encodedAddrs[j] = addr.EncodeAddress()
		}

		outputs[i] = &pb.DecodedTransaction_Output{
			Index:              uint32(i),
			Value:              v.Value,
			Version:            int32(v.Version),
			Addresses:          encodedAddrs,
			Script:             v.PkScript,
			ScriptAsm:          disbuf,
			ScriptClass:        pb.DecodedTransaction_Output_ScriptClass(scriptClass),
			RequiredSignatures: int32(reqSigs),
		}
		if commitAmt != nil {
			outputs[i].CommitmentAmount = int64(*commitAmt)
		}
	}

	return outputs
}

func (s *decodeMessageServer) DecodeRawTransaction(ctx context.Context, req *pb.DecodeRawTransactionRequest) (
	*pb.DecodeRawTransactionResponse, error) {

	serializedTx := req.SerializedTransaction

	var mtx wire.MsgTx
	err := mtx.Deserialize(bytes.NewReader(serializedTx))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Could not decode Tx: %v",
			err)
	}

	txHash := mtx.TxHash()
	resp := &pb.DecodeRawTransactionResponse{
		Transaction: &pb.DecodedTransaction{
			TransactionHash: txHash[:],
			TransactionType: marshalTxType(wallet.TxTransactionType(&mtx)),
			Version:         int32(mtx.Version),
			LockTime:        mtx.LockTime,
			Expiry:          mtx.Expiry,
			Inputs:          marshalDecodedTxInputs(&mtx),
			Outputs:         marshalDecodedTxOutputs(&mtx, s.chainParams),
		},
	}

	return resp, nil
}

func (s *walletServer) BestBlock(ctx context.Context, req *pb.BestBlockRequest) (*pb.BestBlockResponse, error) {
	hash, height := s.wallet.MainChainTip()
	resp := &pb.BestBlockResponse{
		Hash:   hash[:],
		Height: uint32(height),
	}
	return resp, nil
}
