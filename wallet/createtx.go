// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2017 The Decred developers
// Copyright (c) 2018-2019 The Endurio developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"time"

	"github.com/endurio/ndrd/chaincfg"
	"github.com/endurio/ndrd/chaincfg/chainec"
	"github.com/endurio/ndrd/chaincfg/chainhash"
	"github.com/endurio/ndrd/mempool"
	"github.com/endurio/ndrd/ndrutil"
	"github.com/endurio/ndrd/txscript"
	"github.com/endurio/ndrd/types"
	"github.com/endurio/ndrd/wire"
	"github.com/endurio/ndrw/errors"
	"github.com/endurio/ndrw/wallet/internal/txsizes"
	"github.com/endurio/ndrw/wallet/txauthor"
	"github.com/endurio/ndrw/wallet/txrules"
	"github.com/endurio/ndrw/wallet/udb"
	"github.com/endurio/ndrw/wallet/walletdb"
)

// --------------------------------------------------------------------------------
// Constants and simple functions

const (
	// maxStandardTxSize is the maximum size allowed for transactions that
	// are considered standard and will therefore be relayed and considered
	// for mining.
	// TODO: import from ndrd.
	maxStandardTxSize = 100000

	// sanityVerifyFlags are the flags used to enable and disable features of
	// the txscript engine used for sanity checking of transactions signed by
	// the wallet.
	sanityVerifyFlags = mempool.BaseStandardVerifyFlags
)

var (
	// maxTxSize is the maximum size of a transaction we can
	// build with the wallet.
	maxTxSize = chaincfg.MainNetParams.MaxTxSize
)

// extendedOutPoint is a UTXO with an amount.
type extendedOutPoint struct {
	op       *wire.OutPoint
	amt      int64
	pkScript []byte
}

// --------------------------------------------------------------------------------
// Transaction creation

// OutputSelectionAlgorithm specifies the algorithm to use when selecting outputs
// to construct a transaction.
type OutputSelectionAlgorithm uint

const (
	// OutputSelectionAlgorithmDefault describes the default output selection
	// algorithm.  It is not optimized for any particular use case.
	OutputSelectionAlgorithmDefault = iota

	// OutputSelectionAlgorithmAll describes the output selection algorithm of
	// picking every possible availble output.  This is useful for sweeping.
	OutputSelectionAlgorithmAll
)

// NewUnsignedTransaction constructs an unsigned transaction using unspent
// account outputs.
//
// The changeSource parameter is optional and can be nil.  When nil, and if a
// change output should be added, an internal change address is created for the
// account.
func (w *Wallet) NewUnsignedTransaction(outputs []*wire.TxOut, relayFeePerKb types.Amount, account uint32, minConf int32,
	algo OutputSelectionAlgorithm, changeSource txauthor.ChangeSource) (*txauthor.AuthoredTx, error) {

	const op errors.Op = "wallet.NewUnsignedTransaction"

	var authoredTx *txauthor.AuthoredTx
	var changeSourceUpdates []func(walletdb.ReadWriteTx) error
	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)
		_, tipHeight := w.TxStore.MainChainTip(txmgrNs)

		if account != udb.ImportedAddrAccount {
			lastAcct, err := w.Manager.LastAccount(addrmgrNs)
			if err != nil {
				return err
			}
			if account > lastAcct {
				return errors.E(errors.NotExist, "missing account")
			}
		}

		sourceImpl := w.TxStore.MakeInputSource(txmgrNs, addrmgrNs, account,
			minConf, tipHeight)
		var inputSource txauthor.InputSource
		switch algo {
		case OutputSelectionAlgorithmDefault:
			inputSource = sourceImpl.SelectInputs
		case OutputSelectionAlgorithmAll:
			// Wrap the source with one that always fetches the max amount
			// available and ignores insufficient balance issues.
			inputSource = func(types.Amount) (*txauthor.InputDetail, error) {
				inputDetail, err := sourceImpl.SelectInputs(types.MaxAmount)
				if errors.Is(errors.InsufficientBalance, err) {
					err = nil
				}
				return inputDetail, err
			}
		default:
			return errors.E(errors.Invalid,
				errors.Errorf("unknown output selection algorithm %v", algo))
		}

		if changeSource == nil {
			changeSource = &p2PKHChangeSource{
				persist: w.deferPersistReturnedChild(&changeSourceUpdates),
				account: account,
				wallet:  w,
			}
		}

		var err error
		authoredTx, err = txauthor.NewUnsignedTransaction(outputs, relayFeePerKb,
			inputSource, changeSource)
		return err
	})
	if err != nil {
		return nil, errors.E(op, err)
	}
	if len(changeSourceUpdates) != 0 {
		err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			for _, up := range changeSourceUpdates {
				err := up(tx)
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return nil, errors.E(op, err)
		}
	}
	return authoredTx, nil
}

// secretSource is an implementation of txauthor.SecretSource for the wallet's
// address manager.
type secretSource struct {
	*udb.Manager
	addrmgrNs walletdb.ReadBucket
	doneFuncs []func()
}

func (s *secretSource) GetKey(addr ndrutil.Address) (chainec.PrivateKey, bool, error) {
	privKey, done, err := s.Manager.PrivateKey(s.addrmgrNs, addr)
	if err != nil {
		return nil, false, err
	}
	s.doneFuncs = append(s.doneFuncs, done)
	return privKey, true, nil
}

func (s *secretSource) GetScript(addr ndrutil.Address) ([]byte, error) {
	script, done, err := s.Manager.RedeemScript(s.addrmgrNs, addr)
	if err != nil {
		return nil, err
	}
	s.doneFuncs = append(s.doneFuncs, done)
	return script, nil
}

// CreatedTx holds the state of a newly-created transaction and the change
// output (if one was added).
type CreatedTx struct {
	MsgTx       *wire.MsgTx
	ChangeAddr  ndrutil.Address
	ChangeIndex int // negative if no change
	Fee         types.Amount
}

// insertIntoTxMgr inserts a newly created transaction into the tx store
// as unconfirmed.
func (w *Wallet) insertIntoTxMgr(ns walletdb.ReadWriteBucket, msgTx *wire.MsgTx) (*udb.TxRecord, error) {
	// Create transaction record and insert into the db.
	rec, err := udb.NewTxRecordFromMsgTx(msgTx, time.Now())
	if err != nil {
		return nil, err
	}
	err = w.TxStore.InsertMemPoolTx(ns, rec)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

func (w *Wallet) insertCreditsIntoTxMgr(op errors.Op, tx walletdb.ReadWriteTx, msgTx *wire.MsgTx, rec *udb.TxRecord) error {
	addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
	txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)

	// Check every output to determine whether it is controlled by a wallet
	// key.  If so, mark the output as a credit.
	for i, output := range msgTx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(output.Version,
			output.PkScript, w.chainParams)
		if err != nil {
			// Non-standard outputs are skipped.
			continue
		}
		for _, addr := range addrs {
			ma, err := w.Manager.Address(addrmgrNs, addr)
			if err == nil {
				// TODO: Credits should be added with the
				// account they belong to, so wtxmgr is able to
				// track per-account balances.
				err = w.TxStore.AddCredit(txmgrNs, rec, nil,
					uint32(i), ma.Internal(), ma.Account())
				if err != nil {
					return errors.E(op, err)
				}
				err = w.markUsedAddress(op, tx, ma)
				if err != nil {
					return err
				}
				log.Debugf("Marked address %v used", addr)
				continue
			}

			// Missing addresses are skipped.  Other errors should
			// be propagated.
			if !errors.Is(errors.NotExist, err) {
				return errors.E(op, err)
			}
		}
	}

	return nil
}

// insertMultisigOutIntoTxMgr inserts a multisignature output into the
// transaction store database.
func (w *Wallet) insertMultisigOutIntoTxMgr(ns walletdb.ReadWriteBucket, msgTx *wire.MsgTx, index uint32) error {
	// Create transaction record and insert into the db.
	rec, err := udb.NewTxRecordFromMsgTx(msgTx, time.Now())
	if err != nil {
		return err
	}

	return w.TxStore.AddMultisigOut(ns, rec, nil, index)
}

// checkHighFees performs a high fee check if enabled and possible, returning an
// error if the transaction pays high fees.
func (w *Wallet) checkHighFees(totalInput types.Amount, tx *wire.MsgTx) error {
	if w.AllowHighFees {
		return nil
	}
	if txrules.PaysHighFees(totalInput, tx) {
		return errors.E(errors.Policy, "high fee")
	}
	return nil
}

// txToOutputs creates a transaction, selecting previous outputs from an account
// with no less than minconf confirmations, and creates a signed transaction
// that pays to each of the outputs.
func (w *Wallet) txToOutputs(op errors.Op, outputs []*wire.TxOut, account uint32,
	minconf int32, randomizeChangeIdx bool) (*txauthor.AuthoredTx, error) {

	n, err := w.NetworkBackend()
	if err != nil {
		return nil, errors.E(op, err)
	}

	return w.txToOutputsInternal(op, outputs, account, minconf, n,
		randomizeChangeIdx, w.RelayFee())
}

// txToOutputsInternal creates a signed transaction which includes each output
// from outputs.  Previous outputs to reedeem are chosen from the passed
// account's UTXO set and minconf policy. An additional output may be added to
// return change to the wallet.  An appropriate fee is included based on the
// wallet's current relay fee.  The wallet must be unlocked to create the
// transaction.  The address pool passed must be locked and engaged in an
// address pool batch call.
//
// Decred: This func also sends the transaction, and if successful, inserts it
// into the database, rather than delegating this work to the caller as
// btcwallet does.
func (w *Wallet) txToOutputsInternal(op errors.Op, outputs []*wire.TxOut, account uint32, minconf int32,
	n NetworkBackend, randomizeChangeIdx bool, txFee types.Amount) (*txauthor.AuthoredTx, error) {

	var atx *txauthor.AuthoredTx
	var changeSourceUpdates []func(walletdb.ReadWriteTx) error
	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

		// Create the unsigned transaction.
		_, tipHeight := w.TxStore.MainChainTip(txmgrNs)
		inputSource := w.TxStore.MakeInputSource(txmgrNs, addrmgrNs, account,
			minconf, tipHeight)
		changeSource := &p2PKHChangeSource{
			persist: w.deferPersistReturnedChild(&changeSourceUpdates),
			account: account,
			wallet:  w,
		}
		var err error
		atx, err = txauthor.NewUnsignedTransaction(outputs, txFee,
			inputSource.SelectInputs, changeSource)
		if err != nil {
			return err
		}

		// Randomize change position, if change exists, before signing.  This
		// doesn't affect the serialize size, so the change amount will still be
		// valid.
		if atx.ChangeIndex >= 0 && randomizeChangeIdx {
			atx.RandomizeChangePosition()
		}

		// Sign the transaction
		secrets := &secretSource{Manager: w.Manager, addrmgrNs: addrmgrNs}
		err = atx.AddAllInputScripts(secrets)
		for _, done := range secrets.doneFuncs {
			done()
		}
		return err
	})
	if err != nil {
		return nil, errors.E(op, err)
	}

	// Ensure valid signatures were created.
	err = validateMsgTx(op, atx.Tx, atx.PrevScripts)
	if err != nil {
		return nil, errors.E(op, err)
	}

	// Warn when spending UTXOs controlled by imported keys created change for
	// the default account.
	if atx.ChangeIndex >= 0 && account == udb.ImportedAddrAccount {
		changeAmount := types.Amount(atx.Tx.TxOut[atx.ChangeIndex].Value)
		log.Warnf("Spend from imported account produced change: moving"+
			" %v from imported account into default account.", changeAmount)
	}

	err = w.checkHighFees(atx.TotalInput, atx.Tx)
	if err != nil {
		return nil, errors.E(op, err)
	}

	rec, err := udb.NewTxRecordFromMsgTx(atx.Tx, time.Now())
	if err != nil {
		return nil, errors.E(op, err)
	}

	// To avoid a race between publishing a transaction and potentially opening
	// a database view during PublishTransaction, the update must be committed
	// before publishing the transaction to the network.
	var watch []wire.OutPoint
	err = walletdb.Update(w.db, func(dbtx walletdb.ReadWriteTx) error {
		for _, up := range changeSourceUpdates {
			err := up(dbtx)
			if err != nil {
				return err
			}
		}

		// TODO: this can be improved by not using the same codepath as notified
		// relevant transactions, since this does a lot of extra work.
		var err error
		watch, err = w.processTransactionRecord(dbtx, rec, nil, nil)
		return err
	})
	if err != nil {
		return nil, errors.E(op, err)
	}
	err = n.PublishTransactions(context.TODO(), atx.Tx)
	if err != nil {
		return nil, errors.E(op, err)
	}

	// Watch for future relevant transactions.
	err = walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		return w.watchFutureAddresses(dbtx)
	})
	if err != nil {
		log.Errorf("Failed to watch for future address usage after publishing "+
			"transaction: %v", err)
	}
	if len(watch) > 0 {
		err := n.LoadTxFilter(context.TODO(), false, nil, watch)
		if err != nil {
			log.Errorf("Failed to watch outpoints: %v", err)
		}
	}
	return atx, nil
}

// txToMultisig spends funds to a multisig output, partially signs the
// transaction, then returns fund
func (w *Wallet) txToMultisig(op errors.Op, account uint32, amount types.Amount, pubkeys []*ndrutil.AddressSecpPubKey,
	nRequired int8, minconf int32) (*CreatedTx, ndrutil.Address, []byte, error) {

	var (
		ctx      *CreatedTx
		addr     ndrutil.Address
		msScript []byte
	)
	err := walletdb.Update(w.db, func(dbtx walletdb.ReadWriteTx) error {
		var err error
		ctx, addr, msScript, err = w.txToMultisigInternal(op, dbtx,
			account, amount, pubkeys, nRequired, minconf)
		return err
	})
	if err != nil {
		return nil, nil, nil, errors.E(op, err)
	}
	return ctx, addr, msScript, nil
}

func (w *Wallet) txToMultisigInternal(op errors.Op, dbtx walletdb.ReadWriteTx, account uint32, amount types.Amount,
	pubkeys []*ndrutil.AddressSecpPubKey, nRequired int8, minconf int32) (*CreatedTx, ndrutil.Address, []byte, error) {

	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)

	txToMultisigError := func(err error) (*CreatedTx, ndrutil.Address, []byte, error) {
		return nil, nil, nil, err
	}

	n, err := w.NetworkBackend()
	if err != nil {
		return txToMultisigError(err)
	}

	// Get current block's height and hash.
	_, topHeight := w.TxStore.MainChainTip(txmgrNs)

	// Add in some extra for fees. TODO In the future, make a better
	// fee estimator.
	var feeEstForTx types.Amount
	switch w.chainParams.Net {
	case wire.MainNet:
		feeEstForTx = 5e7
	case 0x48e7a065: // testnet2
		feeEstForTx = 5e7
	case wire.TestNet3:
		feeEstForTx = 5e7
	default:
		feeEstForTx = 3e4
	}
	amountRequired := amount + feeEstForTx

	// Instead of taking reward addresses by arg, just create them now  and
	// automatically find all eligible outputs from all current utxos.
	eligible, err := w.findEligibleOutputsAmount(dbtx, account, minconf,
		amountRequired, topHeight)
	if err != nil {
		return txToMultisigError(errors.E(op, err))
	}
	if eligible == nil {
		return txToMultisigError(errors.E(op, "not enough funds to send to multisig address"))
	}

	msgtx := wire.NewMsgTx()
	scriptSizes := make([]int, 0, len(eligible))
	// Fill out inputs.
	forSigning := make([]udb.Credit, 0, len(eligible))
	totalInput := types.Amount(0)
	for _, e := range eligible {
		txIn := wire.NewTxIn(&e.OutPoint, e.Amount, nil)
		msgtx.AddTxIn(txIn)
		totalInput += e.Amount
		forSigning = append(forSigning, e)
		scriptSizes = append(scriptSizes, txsizes.RedeemP2SHSigScriptSize)
	}

	// Insert a multi-signature output, then insert this P2SH
	// hash160 into the address manager and the transaction
	// manager.
	msScript, err := txscript.MultiSigScript(pubkeys, int(nRequired))
	if err != nil {
		return txToMultisigError(errors.E(op, err))
	}
	_, err = w.Manager.ImportScript(addrmgrNs, msScript)
	if err != nil {
		// We don't care if we've already used this address.
		if !errors.Is(errors.Exist, err) {
			return txToMultisigError(errors.E(op, err))
		}
	}
	err = w.TxStore.InsertTxScript(txmgrNs, msScript)
	if err != nil {
		return txToMultisigError(errors.E(op, err))
	}
	scAddr, err := ndrutil.NewAddressScriptHash(msScript, w.chainParams)
	if err != nil {
		return txToMultisigError(errors.E(op, err))
	}
	p2shScript, err := txscript.PayToAddrScript(scAddr)
	if err != nil {
		return txToMultisigError(errors.E(op, err))
	}
	txout := wire.NewTxOut(amount, p2shScript)
	msgtx.AddTxOut(txout)

	// Add change if we need it. The case in which
	// totalInput == amount+feeEst is skipped because
	// we don't need to add a change output in this
	// case.
	feeSize := txsizes.EstimateSerializeSize(scriptSizes, msgtx.TxOut, 0)
	feeEst := txrules.FeeForSerializeSize(w.RelayFee(), feeSize)

	if totalInput < amount+feeEst {
		return txToMultisigError(errors.E(op, errors.InsufficientBalance))
	}
	if totalInput > amount+feeEst {
		changeSource := p2PKHChangeSource{
			persist: w.persistReturnedChild(dbtx),
			account: account,
			wallet:  w,
		}

		pkScript, _, err := changeSource.Script()
		if err != nil {
			return txToMultisigError(err)
		}
		change := totalInput - (amount + feeEst)
		msgtx.AddTxOut(wire.NewTxOut(change, pkScript))
	}

	err = w.signP2PKHMsgTx(msgtx, forSigning, addrmgrNs)
	if err != nil {
		return txToMultisigError(errors.E(op, err))
	}

	err = w.checkHighFees(totalInput, msgtx)
	if err != nil {
		return txToMultisigError(errors.E(op, err))
	}

	err = n.PublishTransactions(context.TODO(), msgtx)
	if err != nil {
		return txToMultisigError(errors.E(op, err))
	}

	// Request updates from ndrd for new transactions sent to this
	// script hash address.
	err = n.LoadTxFilter(context.TODO(), false, []ndrutil.Address{scAddr}, nil)
	if err != nil {
		return txToMultisigError(errors.E(op, err))
	}

	err = w.insertMultisigOutIntoTxMgr(txmgrNs, msgtx, 0)
	if err != nil {
		return txToMultisigError(errors.E(op, err))
	}

	ctx := &CreatedTx{
		MsgTx:       msgtx,
		ChangeAddr:  nil,
		ChangeIndex: -1,
	}

	return ctx, scAddr, msScript, nil
}

// validateMsgTx verifies transaction input scripts for tx.  All previous output
// scripts from outputs redeemed by the transaction, in the same order they are
// spent, must be passed in the prevScripts slice.
func validateMsgTx(op errors.Op, tx *wire.MsgTx, prevScripts [][]byte) error {
	for i, prevScript := range prevScripts {
		vm, err := txscript.NewEngine(prevScript, tx, i,
			sanityVerifyFlags, txscript.DefaultScriptVersion, nil)
		if err != nil {
			return errors.E(op, err)
		}
		err = vm.Execute()
		if err != nil {
			prevOut := &tx.TxIn[i].PreviousOutPoint
			sigScript := tx.TxIn[i].SignatureScript

			log.Errorf("Script validation failed (outpoint %v pkscript %v sigscript %v): %v",
				prevOut, prevScript, sigScript, err)
			return errors.E(op, errors.ScriptFailure, err)
		}
	}
	return nil
}

func creditScripts(credits []udb.Credit) [][]byte {
	scripts := make([][]byte, 0, len(credits))
	for _, c := range credits {
		scripts = append(scripts, c.PkScript)
	}
	return scripts
}

// compressWallet compresses all the utxos in a wallet into a single change
// address. For use when it becomes dusty.
func (w *Wallet) compressWallet(op errors.Op, maxNumIns int, account uint32, changeAddr ndrutil.Address) (*chainhash.Hash, error) {
	var hash *chainhash.Hash
	err := walletdb.Update(w.db, func(dbtx walletdb.ReadWriteTx) error {
		var err error
		hash, err = w.compressWalletInternal(op, dbtx, maxNumIns, account, changeAddr)
		return err
	})
	if err != nil {
		return nil, errors.E(op, err)
	}
	return hash, nil
}

func (w *Wallet) compressWalletInternal(op errors.Op, dbtx walletdb.ReadWriteTx, maxNumIns int, account uint32,
	changeAddr ndrutil.Address) (*chainhash.Hash, error) {

	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)

	n, err := w.NetworkBackend()
	if err != nil {
		return nil, errors.E(op, err)
	}

	// Get current block's height
	_, tipHeight := w.TxStore.MainChainTip(txmgrNs)

	minconf := int32(1)
	eligible, err := w.findEligibleOutputs(dbtx, account, minconf, tipHeight)
	if err != nil {
		return nil, errors.E(op, err)
	}

	if len(eligible) <= 1 {
		return nil, errors.E(op, "too few outputs to consolidate")
	}

	// Check if output address is default, and generate a new adress if needed
	if changeAddr == nil {
		changeAddr, err = w.newChangeAddress(op, w.persistReturnedChild(dbtx), account)
		if err != nil {
			return nil, errors.E(op, err)
		}
	}
	pkScript, err := txscript.PayToAddrScript(changeAddr)
	if err != nil {
		return nil, errors.E(op, errors.Bug, err)
	}
	msgtx := wire.NewMsgTx()
	msgtx.AddTxOut(wire.NewTxOut(0, pkScript))
	maximumTxSize := maxTxSize
	if w.chainParams.Net == wire.MainNet {
		maximumTxSize = maxStandardTxSize
	}

	// Add the txins using all the eligible outputs.
	totalAdded := types.Amount(0)
	scriptSizes := make([]int, 0, maxNumIns)
	forSigning := make([]udb.Credit, 0, maxNumIns)
	count := 0
	for _, e := range eligible {
		if count >= maxNumIns {
			break
		}
		// Add the size of a wire.OutPoint
		if msgtx.SerializeSize() > maximumTxSize {
			break
		}

		txIn := wire.NewTxIn(&e.OutPoint, e.Amount, nil)
		msgtx.AddTxIn(txIn)
		totalAdded += e.Amount
		forSigning = append(forSigning, e)
		scriptSizes = append(scriptSizes, txsizes.RedeemP2PKHSigScriptSize)
		count++
	}

	// Get an initial fee estimate based on the number of selected inputs
	// and added outputs, with no change.
	szEst := txsizes.EstimateSerializeSize(scriptSizes, msgtx.TxOut, 0)
	feeEst := txrules.FeeForSerializeSize(w.RelayFee(), szEst)

	msgtx.TxOut[0].Value = totalAdded - feeEst

	err = w.signP2PKHMsgTx(msgtx, forSigning, addrmgrNs)
	if err != nil {
		return nil, errors.E(op, err)
	}
	err = validateMsgTx(op, msgtx, creditScripts(forSigning))
	if err != nil {
		return nil, errors.E(op, err)
	}

	err = w.checkHighFees(totalAdded, msgtx)
	if err != nil {
		return nil, errors.E(op, err)
	}

	err = n.PublishTransactions(context.TODO(), msgtx)
	if err != nil {
		return nil, errors.E(op, err)
	}

	// Insert the transaction and credits into the transaction manager.
	rec, err := w.insertIntoTxMgr(txmgrNs, msgtx)
	if err != nil {
		return nil, errors.E(op, err)
	}
	err = w.insertCreditsIntoTxMgr(op, dbtx, msgtx, rec)
	if err != nil {
		return nil, err
	}

	txHash := msgtx.TxHash()
	log.Infof("Successfully consolidated funds in transaction %v", &txHash)

	return &txHash, nil
}

func (w *Wallet) findEligibleOutputs(dbtx walletdb.ReadTx, account uint32, minconf int32,
	currentHeight int32) ([]udb.Credit, error) {

	addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

	unspent, err := w.TxStore.UnspentOutputs(txmgrNs)
	if err != nil {
		return nil, err
	}

	// TODO: Eventually all of these filters (except perhaps output locking)
	// should be handled by the call to UnspentOutputs (or similar).
	// Because one of these filters requires matching the output script to
	// the desired account, this change depends on making wtxmgr a waddrmgr
	// dependancy and requesting unspent outputs for a single account.
	eligible := make([]udb.Credit, 0, len(unspent))
	for i := range unspent {
		output := unspent[i]

		// Only include this output if it meets the required number of
		// confirmations.  Coinbase transactions must have have reached
		// maturity before their outputs may be spent.
		if !confirmed(minconf, output.Height, currentHeight) {
			continue
		}

		// Locked unspent outputs are skipped.
		if w.LockedOutpoint(output.OutPoint) {
			continue
		}

		// Filter out unspendable outputs, that is, remove those that
		// (at this time) are not P2PKH outputs.  Other inputs must be
		// manually included in transactions and sent (for example,
		// using createrawtransaction, signrawtransaction, and
		// sendrawtransaction).
		class, addrs, _, err := txscript.ExtractPkScriptAddrs(
			txscript.DefaultScriptVersion, output.PkScript, w.chainParams)
		if err != nil || len(addrs) != 1 {
			continue
		}

		// Make sure everything we're trying to spend is actually mature.
		switch {
		case class == txscript.PubKeyHashTy:
			if output.FromCoinBase {
				if !coinbaseMatured(w.chainParams, output.Height, currentHeight) {
					continue
				}
			}
		default:
			continue
		}

		// Only include the output if it is associated with the passed
		// account.
		//
		// TODO: Handle multisig outputs by determining if enough of the
		// addresses are controlled.
		addrAcct, err := w.Manager.AddrAccount(addrmgrNs, addrs[0])
		if err != nil || addrAcct != account {
			continue
		}

		eligible = append(eligible, *output)
	}
	return eligible, nil
}

// FindEligibleOutputs is the exported version of findEligibleOutputs (which
// tried to find unspent outputs that pass a maturity check).
func (w *Wallet) FindEligibleOutputs(account uint32, minconf int32, currentHeight int32) ([]udb.Credit, error) {
	const op errors.Op = "wallet.FindEligibleOutputs"

	var unspentOutputs []udb.Credit
	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		var err error
		unspentOutputs, err = w.findEligibleOutputs(dbtx, account, minconf, currentHeight)
		return err
	})
	if err != nil {
		return nil, errors.E(op, err)
	}
	return unspentOutputs, nil
}

// findEligibleOutputsAmount uses wtxmgr to find a number of unspent outputs
// while doing maturity checks there.
func (w *Wallet) findEligibleOutputsAmount(dbtx walletdb.ReadTx, account uint32, minconf int32,
	amount types.Amount, currentHeight int32) ([]udb.Credit, error) {
	addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)
	var outTotal types.Amount

	unspent, err := w.TxStore.UnspentOutputsForAmount(txmgrNs, addrmgrNs,
		amount, currentHeight, minconf, false, account)
	if err != nil {
		return nil, err
	}

	eligible := make([]udb.Credit, 0, len(unspent))
	for i := range unspent {
		output := unspent[i]

		// Locked unspent outputs are skipped.
		if w.LockedOutpoint(output.OutPoint) {
			continue
		}

		// Filter out unspendable outputs, that is, remove those that
		// (at this time) are not P2PKH outputs.  Other inputs must be
		// manually included in transactions and sent (for example,
		// using createrawtransaction, signrawtransaction, and
		// sendrawtransaction).
		class, addrs, _, err := txscript.ExtractPkScriptAddrs(
			txscript.DefaultScriptVersion, output.PkScript, w.chainParams)
		if err != nil ||
			!(class == txscript.PubKeyHashTy) {
			continue
		}

		// Only include the output if it is associated with the passed
		// account.  There should only be one address since this is a
		// P2PKH script.
		addrAcct, err := w.Manager.AddrAccount(addrmgrNs, addrs[0])
		if err != nil || addrAcct != account {
			continue
		}

		eligible = append(eligible, *output)
		outTotal += output.Amount
	}

	if outTotal < amount {
		return nil, nil
	}

	return eligible, nil
}

// signP2PKHMsgTx sets the SignatureScript for every item in msgtx.TxIn.
// It must be called every time a msgtx is changed.
// Only P2PKH outputs are supported at this point.
func (w *Wallet) signP2PKHMsgTx(msgtx *wire.MsgTx, prevOutputs []udb.Credit, addrmgrNs walletdb.ReadBucket) error {
	if len(prevOutputs) != len(msgtx.TxIn) {
		return errors.Errorf(
			"Number of prevOutputs (%d) does not match number of tx inputs (%d)",
			len(prevOutputs), len(msgtx.TxIn))
	}
	for i, output := range prevOutputs {
		// Errors don't matter here, as we only consider the
		// case where len(addrs) == 1.
		_, addrs, _, _ := txscript.ExtractPkScriptAddrs(
			txscript.DefaultScriptVersion, output.PkScript, w.chainParams)
		if len(addrs) != 1 {
			continue
		}
		apkh, ok := addrs[0].(*ndrutil.AddressPubKeyHash)
		if !ok {
			return errors.E(errors.Bug, "previous output address is not P2PKH")
		}

		privKey, done, err := w.Manager.PrivateKey(addrmgrNs, apkh)
		if err != nil {
			return err
		}
		defer done()

		sigscript, err := txscript.SignatureScript(msgtx, i, output.PkScript,
			txscript.SigHashAll, privKey, true)
		if err != nil {
			return errors.E(errors.Op("txscript.SignatureScript"), err)
		}
		msgtx.TxIn[i].SignatureScript = sigscript
	}

	return nil
}
