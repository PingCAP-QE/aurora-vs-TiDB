package main

import (
	"fmt"
	"os"
)

func createResultsFile(dbInstanceClass, testType string) (*os.File, error) {
	resultsDir := "results"
	if _, err := os.Stat(resultsDir); os.IsNotExist(err) {
		err := os.MkdirAll(resultsDir, 0755)
		if err != nil {
			return nil, err
		}
	}
	resultsFileName := fmt.Sprintf("results/%s-%s.log", dbInstanceClass, testType)
	file, err := os.Create(resultsFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to create results file: %v", err)
	}
	return file, nil
}
