package keymaster

import (
	"fmt"
	"github.com/pkg/errors"
	"reflect"
	"sort"
)

// MapDiff compares two maps, and returns the first place they differ
func MapDiff(expected map[string]interface{}, actual map[string]interface{}) (err error) {
	expectedKeys := make([]string, 0)
	actualKeys := make([]string, 0)

	for k := range expected {
		expectedKeys = append(expectedKeys, k)
	}

	for k := range actual {
		actualKeys = append(actualKeys, k)
	}

	sort.Strings(expectedKeys)
	sort.Strings(actualKeys)

	for _, k := range expectedKeys {
		//fmt.Printf("%s: %s vs %s\n", k, expected[k], actual[k])
		if !reflect.DeepEqual(expected[k], actual[k]) {
			err = errors.New(fmt.Sprintf("Maps differ at %s: %s vs %s", k, expected[k], actual[k]))
			return err
		}
	}

	return err
}

// AnonymizeStringArray turns an []string into []interface{} so that we can use reflect.DeepEqual() to compare.
func AnonymizeStringArray(input []string) (output []interface{}) {
	output = make([]interface{}, 0)
	for _, i := range input {
		output = append(output, i)
	}

	return output
}

// PartialMatch compares two maps, and returns true if the keys you care about match.  Other keys are ignored
func PartialMatch(matchKeys []string, expected map[string]interface{}, actual map[string]interface{}) (err error) {
	if reflect.TypeOf(expected) != reflect.TypeOf(actual) {
		err = errors.New(fmt.Sprintf("Type mismatch: %s vs %s", reflect.TypeOf(expected).String(), reflect.TypeOf(actual).String()))
		return err
	}
	for _, k := range matchKeys {
		if reflect.TypeOf(expected[k]) != reflect.TypeOf(actual[k]) {
			err = errors.New(fmt.Sprintf("Type mismatch at %s: %s vs %s", k, reflect.TypeOf(expected).String(), reflect.TypeOf(actual).String()))
			return err
		}
		if !reflect.DeepEqual(expected[k], actual[k]) {
			err = errors.New(fmt.Sprintf("Mismatch at %s: %q vs %q", k, expected[k], actual[k]))
			return err
		}
	}

	return err
}
