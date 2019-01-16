// Copyright (c) 2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txrules

import (
	"math"
	"sync"

	"github.com/endurio/ndrd/blockchain"
)

// ValidPoolFeeRate tests to see if a pool fee is a valid percentage from
// 0.01% to 100.00%.
func ValidPoolFeeRate(feeRate float64) bool {
	poolFeeRateTest := feeRate * 100
	poolFeeRateTest = math.Floor(poolFeeRateTest)
	return poolFeeRateTest >= 1.0 && poolFeeRateTest <= 10000.0
}

var subsidyCache *blockchain.SubsidyCache
var initSubsidyCacheOnce sync.Once
