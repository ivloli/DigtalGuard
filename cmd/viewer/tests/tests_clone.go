// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Code generated by tailscale.com/cmd/cloner; DO NOT EDIT.

package tests

import (
	"net/netip"
)

// Clone makes a deep copy of StructWithPtrs.
// The result aliases no memory with the original.
func (src *StructWithPtrs) Clone() *StructWithPtrs {
	if src == nil {
		return nil
	}
	dst := new(StructWithPtrs)
	*dst = *src
	if dst.Value != nil {
		dst.Value = new(StructWithoutPtrs)
		*dst.Value = *src.Value
	}
	if dst.Int != nil {
		dst.Int = new(int)
		*dst.Int = *src.Int
	}
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _StructWithPtrsCloneNeedsRegeneration = StructWithPtrs(struct {
	Value        *StructWithoutPtrs
	Int          *int
	NoCloneValue *StructWithoutPtrs
}{})

// Clone makes a deep copy of StructWithoutPtrs.
// The result aliases no memory with the original.
func (src *StructWithoutPtrs) Clone() *StructWithoutPtrs {
	if src == nil {
		return nil
	}
	dst := new(StructWithoutPtrs)
	*dst = *src
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _StructWithoutPtrsCloneNeedsRegeneration = StructWithoutPtrs(struct {
	Int int
	Pfx netip.Prefix
}{})

// Clone makes a deep copy of Map.
// The result aliases no memory with the original.
func (src *Map) Clone() *Map {
	if src == nil {
		return nil
	}
	dst := new(Map)
	*dst = *src
	if dst.Int != nil {
		dst.Int = map[string]int{}
		for k, v := range src.Int {
			dst.Int[k] = v
		}
	}
	if dst.SliceInt != nil {
		dst.SliceInt = map[string][]int{}
		for k := range src.SliceInt {
			dst.SliceInt[k] = append([]int{}, src.SliceInt[k]...)
		}
	}
	if dst.StructPtrWithPtr != nil {
		dst.StructPtrWithPtr = map[string]*StructWithPtrs{}
		for k, v := range src.StructPtrWithPtr {
			dst.StructPtrWithPtr[k] = v.Clone()
		}
	}
	if dst.StructPtrWithoutPtr != nil {
		dst.StructPtrWithoutPtr = map[string]*StructWithoutPtrs{}
		for k, v := range src.StructPtrWithoutPtr {
			dst.StructPtrWithoutPtr[k] = v.Clone()
		}
	}
	if dst.StructWithoutPtr != nil {
		dst.StructWithoutPtr = map[string]StructWithoutPtrs{}
		for k, v := range src.StructWithoutPtr {
			dst.StructWithoutPtr[k] = v
		}
	}
	if dst.SlicesWithPtrs != nil {
		dst.SlicesWithPtrs = map[string][]*StructWithPtrs{}
		for k := range src.SlicesWithPtrs {
			dst.SlicesWithPtrs[k] = append([]*StructWithPtrs{}, src.SlicesWithPtrs[k]...)
		}
	}
	if dst.SlicesWithoutPtrs != nil {
		dst.SlicesWithoutPtrs = map[string][]*StructWithoutPtrs{}
		for k := range src.SlicesWithoutPtrs {
			dst.SlicesWithoutPtrs[k] = append([]*StructWithoutPtrs{}, src.SlicesWithoutPtrs[k]...)
		}
	}
	if dst.StructWithoutPtrKey != nil {
		dst.StructWithoutPtrKey = map[StructWithoutPtrs]int{}
		for k, v := range src.StructWithoutPtrKey {
			dst.StructWithoutPtrKey[k] = v
		}
	}
	if dst.SliceIntPtr != nil {
		dst.SliceIntPtr = map[string][]*int{}
		for k := range src.SliceIntPtr {
			dst.SliceIntPtr[k] = append([]*int{}, src.SliceIntPtr[k]...)
		}
	}
	if dst.PointerKey != nil {
		dst.PointerKey = map[*string]int{}
		for k, v := range src.PointerKey {
			dst.PointerKey[k] = v
		}
	}
	if dst.StructWithPtrKey != nil {
		dst.StructWithPtrKey = map[StructWithPtrs]int{}
		for k, v := range src.StructWithPtrKey {
			dst.StructWithPtrKey[k] = v
		}
	}
	if dst.StructWithPtr != nil {
		dst.StructWithPtr = map[string]StructWithPtrs{}
		for k, v := range src.StructWithPtr {
			v2 := v.Clone()
			dst.StructWithPtr[k] = *v2
		}
	}
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _MapCloneNeedsRegeneration = Map(struct {
	Int                 map[string]int
	SliceInt            map[string][]int
	StructPtrWithPtr    map[string]*StructWithPtrs
	StructPtrWithoutPtr map[string]*StructWithoutPtrs
	StructWithoutPtr    map[string]StructWithoutPtrs
	SlicesWithPtrs      map[string][]*StructWithPtrs
	SlicesWithoutPtrs   map[string][]*StructWithoutPtrs
	StructWithoutPtrKey map[StructWithoutPtrs]int
	SliceIntPtr         map[string][]*int
	PointerKey          map[*string]int
	StructWithPtrKey    map[StructWithPtrs]int
	StructWithPtr       map[string]StructWithPtrs
}{})

// Clone makes a deep copy of StructWithSlices.
// The result aliases no memory with the original.
func (src *StructWithSlices) Clone() *StructWithSlices {
	if src == nil {
		return nil
	}
	dst := new(StructWithSlices)
	*dst = *src
	dst.Values = append(src.Values[:0:0], src.Values...)
	dst.ValuePointers = make([]*StructWithoutPtrs, len(src.ValuePointers))
	for i := range dst.ValuePointers {
		dst.ValuePointers[i] = src.ValuePointers[i].Clone()
	}
	dst.StructPointers = make([]*StructWithPtrs, len(src.StructPointers))
	for i := range dst.StructPointers {
		dst.StructPointers[i] = src.StructPointers[i].Clone()
	}
	dst.Structs = make([]StructWithPtrs, len(src.Structs))
	for i := range dst.Structs {
		dst.Structs[i] = *src.Structs[i].Clone()
	}
	dst.Ints = make([]*int, len(src.Ints))
	for i := range dst.Ints {
		x := *src.Ints[i]
		dst.Ints[i] = &x
	}
	dst.Slice = append(src.Slice[:0:0], src.Slice...)
	dst.Prefixes = append(src.Prefixes[:0:0], src.Prefixes...)
	dst.Data = append(src.Data[:0:0], src.Data...)
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _StructWithSlicesCloneNeedsRegeneration = StructWithSlices(struct {
	Values         []StructWithoutPtrs
	ValuePointers  []*StructWithoutPtrs
	StructPointers []*StructWithPtrs
	Structs        []StructWithPtrs
	Ints           []*int
	Slice          []string
	Prefixes       []netip.Prefix
	Data           []byte
}{})

// Clone makes a deep copy of OnlyGetClone.
// The result aliases no memory with the original.
func (src *OnlyGetClone) Clone() *OnlyGetClone {
	if src == nil {
		return nil
	}
	dst := new(OnlyGetClone)
	*dst = *src
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _OnlyGetCloneCloneNeedsRegeneration = OnlyGetClone(struct {
	SinViewerPorFavor bool
}{})

// Clone makes a deep copy of StructWithEmbedded.
// The result aliases no memory with the original.
func (src *StructWithEmbedded) Clone() *StructWithEmbedded {
	if src == nil {
		return nil
	}
	dst := new(StructWithEmbedded)
	*dst = *src
	dst.A = src.A.Clone()
	dst.StructWithSlices = *src.StructWithSlices.Clone()
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _StructWithEmbeddedCloneNeedsRegeneration = StructWithEmbedded(struct {
	A *StructWithPtrs
	StructWithSlices
}{})
