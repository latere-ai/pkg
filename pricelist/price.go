// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package pricelist

import (
	"encoding/json"
	"math/big"
	"regexp"
	"strings"
)

// Price is one price a model's row states, read from the decimal string of
// USD per token the list writes, such as "0.000000125", as micro-USD per
// million tokens. The zero Price is one the row does not state.
//
// The list writes "-1" for a price set per request, which is no fixed price,
// and some prices round to zero at the micro-unit; PerMillion refuses both.
// An exact zero is told apart from both (Zero), since a price written as "0"
// is a statement that the token costs nothing.
type Price struct {
	state priceState
	micro int64
}

// priceState is what a price string turned out to be.
type priceState uint8

const (
	// priceUnstated is a member that is absent, null, empty or blank.
	priceUnstated priceState = iota
	// priceUnpriced is a stated price that is no fixed price: not a
	// nonnegative decimal, above zero but under half a micro-unit, or past
	// what an int64 count of micro-units holds.
	priceUnpriced
	// priceZero is a price written as exactly zero, such as "0" or
	// "0.000000".
	priceZero
	// pricePriced is a price of at least one micro-unit.
	pricePriced
)

// ParsePrice reads s, a decimal of USD per token as the list writes it, with
// surrounding white space ignored. It never fails: a string that is no price
// is a Price whose PerMillion is not ok.
func ParsePrice(s string) Price {
	s = strings.TrimSpace(s)
	if s == "" {
		return Price{}
	}
	if !decimal.MatchString(s) {
		return Price{state: priceUnpriced}
	}
	v, ok := new(big.Rat).SetString(s)
	if !ok {
		return Price{state: priceUnpriced}
	}
	if v.Sign() == 0 {
		return Price{state: priceZero}
	}
	v.Mul(v, microPerMillion)
	q, rem := new(big.Int).QuoRem(v.Num(), v.Denom(), new(big.Int))
	// Half-even: above half rounds up, exactly half rounds to the even
	// neighbor, so a long run of prices carries no rounding bias.
	switch rem.Lsh(rem, 1).Cmp(v.Denom()) {
	case 1:
		q.Add(q, big.NewInt(1))
	case 0:
		if q.Bit(0) == 1 {
			q.Add(q, big.NewInt(1))
		}
	}
	if q.Sign() <= 0 || !q.IsInt64() {
		return Price{state: priceUnpriced}
	}
	return Price{state: pricePriced, micro: q.Int64()}
}

// PerMillion is the price in micro-USD per million tokens, rounded half-even
// to the micro-unit. The arithmetic is exact: the list writes prices such as
// "0.000000123456789" that a float64 cannot hold. ok is false for a price
// the row does not state, one that is not a nonnegative decimal, one past
// what an int64 holds, and one that is zero or rounds to zero.
func (p Price) PerMillion() (micro int64, ok bool) {
	return p.micro, p.state == pricePriced
}

// Stated reports whether the row states the price at all: false for a
// member that is absent, null, empty or blank.
func (p Price) Stated() bool {
	return p.state != priceUnstated
}

// Zero reports whether the row states the price as exactly zero, such as
// "0" or "0.000000". A price that only rounds to zero is not.
func (p Price) Zero() bool {
	return p.state == priceZero
}

// UnmarshalJSON implements json.Unmarshaler. A price is a JSON string or
// null; any other value fails the decode, as it would for a string field.
func (p *Price) UnmarshalJSON(b []byte) error {
	var s *string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == nil {
		*p = Price{}
		return nil
	}
	*p = ParsePrice(*s)
	return nil
}

// decimal is the form of a price the list writes: a nonnegative decimal,
// possibly in exponent notation with a short exponent. The bound on the
// exponent keeps a hostile list from asking for a 10^huge big.Int.
var decimal = regexp.MustCompile(`^[0-9]*\.?[0-9]+(?:[eE][-+]?[0-9]{1,2})?$`)

// microPerMillion turns USD per token into micro-USD per million tokens:
// 10^6 tokens times 10^6 micro-units.
var microPerMillion = new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(12), nil))
