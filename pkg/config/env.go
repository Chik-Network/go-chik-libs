package config

import (
	"fmt"
	"math/big"
	"os"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/chik-network/go-chik-libs/pkg/types"
	"github.com/chik-network/go-chik-libs/pkg/util"
)

// FillValuesFromEnvironment reads environment variables starting with `chik.` and edits the config based on the config path
// chik.selected_network=mainnet would set the top level `selected_network: mainnet`
// chik.full_node.port=9678 would set full_node.port to 9678
//
// # Complex data structures can be passed in as JSON strings and they will be parsed out into the datatype specified for the config prior to being inserted
//
// chik.network_overrides.constants.mainnet='{"GENESIS_CHALLENGE":"abc123","GENESIS_PRE_FARM_POOL_PUZZLE_HASH":"xyz789"}'
func (c *ChikConfig) FillValuesFromEnvironment() error {
	valuesToUpdate := getAllChikVars()
	for _, pAndV := range valuesToUpdate {
		err := c.SetFieldByPath(pAndV.Path, pAndV.Value)
		if err != nil {
			return err
		}
	}

	return nil
}

// PathAndValue is a struct to represent the path minus any prefix and the value to set
type PathAndValue struct {
	Path  []string
	Value string
}

func getAllChikVars() map[string]PathAndValue {
	// Most shells don't allow `.` in env names, but docker will and its easier to visualize the `.`, so support both
	// `.` and `__` as valid path segment separators
	// chik.full_node.port
	// chik__full_node__port
	envVars := os.Environ()
	return ParsePathsAndValuesFromStrings(envVars, true)
}

// ParsePathsAndValuesFromStrings takes a list of strings and parses out paths and values
// requirePrefix determines if the string must be prefixed with chik. or chik__
// This is typically used when parsing env vars, not so much with flags
func ParsePathsAndValuesFromStrings(pathStrings []string, requirePrefix bool) map[string]PathAndValue {
	separators := []string{".", "__"}
	finalVars := map[string]PathAndValue{}

	for _, sep := range separators {
		prefix := fmt.Sprintf("chik%s", sep)
		for _, env := range pathStrings {
			if requirePrefix {
				if strings.HasPrefix(env, prefix) {
					pair := strings.SplitN(env, "=", 2)
					if len(pair) == 2 {
						finalVars[pair[0][len(prefix):]] = PathAndValue{
							Path:  strings.Split(pair[0], sep)[1:], // This is the Path in the config to the Value to edit minus the "chik" prefix
							Value: pair[1],
						}
					}
				}
			} else {
				pair := strings.SplitN(env, "=", 2)
				if len(pair) == 2 {
					// Ensure that we don't overwrite something that is already in the finalVars
					// UNLESS the path is longer than the value already there
					// Shorter paths can happen if not requiring a prefix and we added the full path
					// in the first iteration, but actually uses a separator later in the list
					path := strings.Split(pair[0], sep)
					if _, set := finalVars[pair[0]]; !set || (set && len(path) > len(finalVars[pair[0]].Path)) {
						finalVars[pair[0]] = PathAndValue{
							Path:  path,
							Value: pair[1],
						}
					}
				}
			}

		}
	}

	return finalVars
}

// ParsePathsFromStrings takes a list of strings and parses out paths
// requirePrefix determines if the string must be prefixed with chik. or chik__
// This is typically used when parsing env vars, not so much with flags
func ParsePathsFromStrings(pathStrings []string, requirePrefix bool) map[string][]string {
	separators := []string{".", "__"}
	finalVars := map[string][]string{}

	for _, sep := range separators {
		prefix := fmt.Sprintf("chik%s", sep)
		for _, env := range pathStrings {
			if requirePrefix {
				if strings.HasPrefix(env, prefix) {
					finalVars[env[len(prefix):]] = strings.Split(env, sep)[1:]
				}
			} else {
				// Ensure that we don't overwrite something that is already in the finalVars
				// UNLESS the path is longer than the value already there
				// Shorter paths can happen if not requiring a prefix and we added the full path
				// in the first iteration, but actually uses a separator later in the list
				path := strings.Split(env, sep)
				if _, set := finalVars[env]; !set || (set && len(path) > len(finalVars[env])) {
					finalVars[env] = path
				}
			}
		}
	}

	return finalVars
}

// SetFieldByPath iterates through each item in path to find the corresponding `yaml` tag in the struct
// Once found, we move to the next item in path and look for that key within the first element
// If any element is not found, an error will be returned
func (c *ChikConfig) SetFieldByPath(path []string, value any) error {
	v := reflect.ValueOf(c).Elem()
	return setFieldByPath(v, path, value)
}

func setFieldByPath(v reflect.Value, path []string, value any) error {
	if len(path) == 0 {
		return fmt.Errorf("invalid path")
	}

	// Deal with pointers
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		yamlTagRaw := field.Tag.Get("yaml")
		yamlTag := strings.Split(yamlTagRaw, ",")[0]

		if yamlTagRaw == ",inline" && field.Anonymous {
			// Check the inline struct
			if err := setFieldByPath(v.Field(i), path, value); err != nil {
				return err
			}
		} else if yamlTag == path[0] {
			// We found a match for the current level of "paths"
			// If we only have 1 element left in paths, then we can set the value
			// Otherwise, we can recursively call setFieldByPath again, with the remaining elements of path
			fieldValue := v.Field(i)
			if fieldValue.Kind() == reflect.Ptr {
				fieldValue = fieldValue.Elem()
			}
			if len(path) > 1 {
				if fieldValue.Kind() == reflect.Map {
					mapKey := reflect.ValueOf(path[1])
					if !mapKey.Type().ConvertibleTo(fieldValue.Type().Key()) {
						return fmt.Errorf("invalid map key type %s", mapKey.Type())
					}
					mapValue := fieldValue.MapIndex(mapKey)
					if !mapValue.IsValid() {
						// Create a new value for the map key
						newMapValue := reflect.New(fieldValue.Type().Elem()).Elem()
						err := doValueSet(newMapValue, path[1:], value)
						if err != nil {
							return err
						}
						fieldValue.SetMapIndex(mapKey, newMapValue)
						return nil
					}
					if !mapValue.CanSet() {
						// Create a new writable map and copy over the existing data
						newMapValue := reflect.New(fieldValue.Type().Elem()).Elem()
						newMapValue.Set(mapValue)
						mapValue = newMapValue
					}
					err := setFieldByPath(mapValue, path[2:], value)
					if err != nil {
						return err
					}
					fieldValue.SetMapIndex(mapKey, mapValue)
					return nil
				} else if fieldValue.Kind() == reflect.Slice && util.IsNumericInt(path[1]) {
					sliceKey, err := strconv.Atoi(path[1])
					if err != nil {
						return fmt.Errorf("unable to parse slice index as int: %w", err)
					}

					if sliceKey >= fieldValue.Len() {
						// Set a zero value and then call back to this function to go the other path
						zeroSliceValue := reflect.Zero(fieldValue.Type().Elem())
						fieldValue.Set(reflect.Append(fieldValue, zeroSliceValue))
					}

					sliceValue := fieldValue.Index(sliceKey)

					if !sliceValue.IsValid() {
						return fmt.Errorf("invalid slice value")
					}
					if len(path) < 3 {
						// This is the case where we're setting the index directly to a single value (not a sub-value in a struct, etc)
						return doValueSet(sliceValue, path[1:], value)
					}
					return setFieldByPath(sliceValue, path[2:], value)
				} else {
					return setFieldByPath(fieldValue, path[1:], value)
				}
			}

			return doValueSet(fieldValue, path, value)
		}
	}

	return nil
}

// GetFieldByPath iterates through each item in path to find the corresponding `yaml` tag in the struct
// Once found, we move to the next item in path and look for that key within the first element
// If any element is not found, an error will be returned
func (c *ChikConfig) GetFieldByPath(path []string) (any, error) {
	v := reflect.ValueOf(c).Elem()
	return getFieldByPath(v, path)
}

func getFieldByPath(v reflect.Value, path []string) (any, error) {
	if len(path) == 0 {
		return nil, fmt.Errorf("invalid path")
	}

	// Handle pointers
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return nil, fmt.Errorf("nil pointer encountered")
		}
		v = v.Elem()
	}

	// Ensure we're working with a struct
	if v.Kind() != reflect.Struct {
		return nil, fmt.Errorf("expected struct but got %s", v.Kind())
	}

	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		yamlTagRaw := field.Tag.Get("yaml")
		yamlTag := strings.Split(yamlTagRaw, ",")[0]

		if yamlTagRaw == ",inline" && field.Anonymous {
			// Dive into the embedded struct
			return getFieldByPath(v.Field(i), path)
		} else if yamlTag == path[0] {
			fieldValue := v.Field(i)

			if fieldValue.Kind() == reflect.Ptr {
				if fieldValue.IsNil() {
					return nil, fmt.Errorf("nil pointer in path at %s", path[0])
				}
				fieldValue = fieldValue.Elem()
			}

			if len(path) == 1 {
				return fieldValue.Interface(), nil
			}

			switch fieldValue.Kind() {
			case reflect.Struct:
				return getFieldByPath(fieldValue, path[1:])
			case reflect.Map:
				mapKey := reflect.ValueOf(path[1])
				if !mapKey.Type().ConvertibleTo(fieldValue.Type().Key()) {
					return nil, fmt.Errorf("invalid map key type %s", mapKey.Type())
				}
				mapValue := fieldValue.MapIndex(mapKey)
				if !mapValue.IsValid() {
					return nil, fmt.Errorf("map key %v not found", mapKey)
				}
				if len(path) == 2 {
					return mapValue.Interface(), nil
				}
				return getFieldByPath(mapValue, path[2:])
			case reflect.Slice:
				if !util.IsNumericInt(path[1]) {
					return nil, fmt.Errorf("expected numeric index for slice")
				}
				sliceIndex, err := strconv.Atoi(path[1])
				if err != nil {
					return nil, fmt.Errorf("unable to parse slice index: %w", err)
				}
				if sliceIndex >= fieldValue.Len() {
					return nil, fmt.Errorf("index %d out of range for slice of length %d", sliceIndex, fieldValue.Len())
				}
				sliceElem := fieldValue.Index(sliceIndex)
				if len(path) == 2 {
					return sliceElem.Interface(), nil
				}
				return getFieldByPath(sliceElem, path[2:])
			default:
				return nil, fmt.Errorf("unexpected kind %s at path %s", fieldValue.Kind(), path[0])
			}
		}
	}

	return nil, fmt.Errorf("field %s not found", path[0])
}

func doValueSet(fieldValue reflect.Value, path []string, value any) error {
	if !fieldValue.CanSet() {
		return fmt.Errorf("cannot set field %s", path[0])
	}

	// Special Cases
	if fieldValue.Type() == reflect.TypeOf(types.Uint128{}) {
		strValue, ok := value.(string)
		if !ok {
			return fmt.Errorf("expected string for Uint128 field, got %T", value)
		}
		bigIntValue := new(big.Int)
		_, ok = bigIntValue.SetString(strValue, 10)
		if !ok {
			return fmt.Errorf("invalid string for big.Int: %s", strValue)
		}
		fieldValue.Set(reflect.ValueOf(types.Uint128FromBig(bigIntValue)))
		return nil
	}

	// Handle YAML (and therefore JSON) parsing for passing in entire structs/maps
	// This is particularly useful if you want to pass in a whole blob of network constants at once
	if fieldValue.Kind() == reflect.Struct || fieldValue.Kind() == reflect.Map || fieldValue.Kind() == reflect.Slice {
		if strValue, ok := value.(string); ok {
			yamlData := []byte(strValue)
			if err := yaml.Unmarshal(yamlData, fieldValue.Addr().Interface()); err != nil {
				return fmt.Errorf("failed to unmarshal yaml into field: %w", err)
			}
			// If we successfully replaced by doing yaml parsing into the field, then we should not try anything else
			return nil
		}
	}

	val := reflect.ValueOf(value)

	if fieldValue.Type() != val.Type() {
		if val.Type().ConvertibleTo(fieldValue.Type()) {
			val = val.Convert(fieldValue.Type())
		} else {
			convertedVal, err := convertValue(value, fieldValue.Type())
			if err != nil {
				return err
			}
			val = reflect.ValueOf(convertedVal)
		}
	}

	fieldValue.Set(val)

	return nil
}

func convertValue(value interface{}, targetType reflect.Type) (interface{}, error) {
	switch targetType.Kind() {
	case reflect.Uint8:
		v, err := strconv.ParseUint(fmt.Sprintf("%v", value), 10, 8)
		if err != nil {
			return nil, err
		}
		return uint8(v), nil
	case reflect.Uint16:
		v, err := strconv.ParseUint(fmt.Sprintf("%v", value), 10, 16)
		if err != nil {
			return nil, err
		}
		return uint16(v), nil
	case reflect.Uint32:
		v, err := strconv.ParseUint(fmt.Sprintf("%v", value), 10, 32)
		if err != nil {
			return nil, err
		}
		return uint32(v), nil
	case reflect.Uint64:
		v, err := strconv.ParseUint(fmt.Sprintf("%v", value), 10, 64)
		if err != nil {
			return nil, err
		}
		return v, nil
	case reflect.Bool:
		v, err := strconv.ParseBool(fmt.Sprintf("%v", value))
		if err != nil {
			return nil, err
		}
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported conversion to %s", targetType.Kind())
	}
}
