// Copyright (c) 2015-2016 The btcsuite developers
// Copyright (c) 2016 The Decred developers
// Copyright (c) 2018-2019 The Endurio developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cfgutil

import (
	"strconv"
	"strings"

	"github.com/endurio/ndrd/types"
)

// AmountFlag embeds a types.Amount and implements the flags.Marshaler and
// Unmarshaler interfaces so it can be used as a config struct field.
type AmountFlag struct {
	types.Amount
}

// NewAmountFlag creates an AmountFlag with a default types.Amount.
func NewAmountFlag(defaultValue types.Amount) *AmountFlag {
	return &AmountFlag{defaultValue}
}

// MarshalFlag satisifes the flags.Marshaler interface.
func (a *AmountFlag) MarshalFlag() (string, error) {
	return a.Amount.String(), nil
}

// UnmarshalFlag satisifes the flags.Unmarshaler interface.
func (a *AmountFlag) UnmarshalFlag(value string) error {
	value = strings.TrimSuffix(value, " NDR")
	valueF64, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return err
	}
	amount, err := types.NewAmount(valueF64)
	if err != nil {
		return err
	}
	a.Amount = amount
	return nil
}
