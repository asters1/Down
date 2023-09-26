package main

import (
	"fmt"
	"testing"
)

func TestMain(t *testing.T) {
	for i := 0; i < 9; i++ {
		if i == 5 {
			continue
		}
		fmt.Println(i)
	}
}
