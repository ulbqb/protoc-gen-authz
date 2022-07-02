package module

import "fmt"

func roleIndexes(roles []string, rules []string) []int {
	indexes := []int{}
	for _, n := range rules {
		index := findIndexOfSlice(roles, n)
		if index < 0 {
			panic(fmt.Sprintf("authz error: %s is not in roles list", n))
		}
		indexes = append(indexes, index)
	}
	return indexes
}

func findIndexOfSlice(list []string, keyword string) int {
	for i, e := range list {
		if e == keyword {
			return i
		}
	}
	return -1
}

func removeDuplicateValuesOfSlice(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}

	// If the key(values of the slice) is not equal
	// to the already present value in new slice (list)
	// then we append it. else we jump on another element.
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
