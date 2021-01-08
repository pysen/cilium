// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ebpf

import (
	"fmt"
	"reflect"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/lock"

	ciliumebpf "github.com/cilium/ebpf"
)

type MapSpec = ciliumebpf.MapSpec

const (
	PerCPUHash = ciliumebpf.PerCPUHash

	PinByName = ciliumebpf.PinByName
)

// IterateCallback represents the signature of the callback function expected by
// the IterateWithCallback method, which in turn is used to iterate all the
// keys/values of a map.
type IterateCallback func(key, value interface{})

// Map represents an eBPF map.
type Map struct {
	*ciliumebpf.Map

	spec       *MapSpec
	key, value interface{}

	path string
	lock lock.RWMutex
}

// NewMap creates a new Map object.
func NewMap(spec *MapSpec, key, value interface{}) *Map {
	return &Map{
		spec:  spec,
		key:   key,
		value: value,
	}
}

// OpenOrCreate tries to open or create the eBPF map identified by the spec in
// the Map object.
func (m *Map) OpenOrCreate() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.Map != nil {
		return nil
	}

	opts := ciliumebpf.MapOptions{
		PinPath: bpf.MapPrefixPath(),
	}

	newMap, err := ciliumebpf.NewMapWithOptions(m.spec, opts)
	if err != nil {
		return fmt.Errorf("unable to create map: %w", err)
	}

	m.Map = newMap
	m.path = bpf.MapPath(m.spec.Name)

	registerMap(m)
	return nil
}

// IterateWithCallback iterates through all the keys/values of a map, passing
// each key/value pair to the cb callback.
func (m *Map) IterateWithCallback(cb IterateCallback) error {
	if m.Map == nil {
		if err := m.OpenOrCreate(); err != nil {
			return err
		}
	}

	m.lock.RLock()
	defer m.lock.RUnlock()

	key := reflect.New(reflect.ValueOf(m.key).Elem().Type()).Interface()
	value := reflect.New(reflect.ValueOf(m.value).Elem().Type()).Interface()

	entries := m.Iterate()
	for entries.Next(key, value) {
		cb(key, value)
	}

	return nil
}

// GetModel returns a BPF map in the representation served via the API.
func (m *Map) GetModel() *models.BPFMap {
	m.lock.RLock()
	defer m.lock.RUnlock()

	mapModel := &models.BPFMap{
		Path: m.path,
	}

	// TODO: handle map cache. See pkg/bpf/map_linux.go:GetModel()

	return mapModel
}
