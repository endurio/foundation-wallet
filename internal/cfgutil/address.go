// Copyright (c) 2015-2016 The btcsuite developers
// Copyright (c) 2016 The Decred developers
// Copyright (c) 2018-2019 The Endurio developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cfgutil

import "github.com/endurio/ndrd/ndrutil"

// AddressFlag contains a ndrutil.Address and implements the flags.Marshaler and
// Unmarshaler interfaces so it can be used as a config struct field.
type AddressFlag struct {
	Address ndrutil.Address
}

// NewAddressFlag creates an AddressFlag with a default ndrutil.Address.
func NewAddressFlag(defaultValue ndrutil.Address) *AddressFlag {
	return &AddressFlag{defaultValue}
}

// MarshalFlag satisifes the flags.Marshaler interface.
func (a *AddressFlag) MarshalFlag() (string, error) {
	if a.Address != nil {
		return a.Address.String(), nil
	}

	return "", nil
}

// UnmarshalFlag satisifes the flags.Unmarshaler interface.
func (a *AddressFlag) UnmarshalFlag(addr string) error {
	if addr == "" {
		a.Address = nil
		return nil
	}
	address, err := ndrutil.DecodeAddress(addr)
	if err != nil {
		return err
	}
	a.Address = address
	return nil
}
