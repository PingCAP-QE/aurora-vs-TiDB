package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// 单个结果文件的解析结果
type BenchmarkResult struct {
	MachineType string
	TestType    string
	Results     map[int]Metrics // 线程数到性能指标的映射
}

type Metrics struct {
	TPS        float64
	QPS        float64
	P95Latency float64
	AvgLatency float64
}

type MetricPattern struct {
	Name  string
	Regex *regexp.Regexp
	Field func(metrics *Metrics, value float64)
}

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

func ParseBenchmarkLog(filePath string) (BenchmarkResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return BenchmarkResult{}, fmt.Errorf("failed to open file %s: %v", filePath, err)
	}
	defer file.Close()

	// 从文件名中提取机型和测试类型
	fileName := strings.TrimSuffix(filePath, ".log")
	parts := strings.Split(fileName, ".")
	machineType := parts[len(parts)-2]
	testType := parts[len(parts)-1]

	result := BenchmarkResult{
		MachineType: machineType,
		TestType:    testType,
		Results:     make(map[int]Metrics),
	}

	// 正则匹配逻辑，如果要其他指标请在这里添加
	metricPatterns := []MetricPattern{
		{"tps", regexp.MustCompile(`transactions: +(\d+) +\(([\d.]+) per sec\.\)`), func(metrics *Metrics, value float64) { metrics.TPS = value }},
		{"qps", regexp.MustCompile(`qps: ([\d.]+)`), func(metrics *Metrics, value float64) { metrics.QPS = value }},
		{"p95_latency", regexp.MustCompile(`95th percentile: +([\d.]+)`), func(metrics *Metrics, value float64) { metrics.P95Latency = value }},
		{"avg_latency", regexp.MustCompile(`avg: +([\d.]+)`), func(metrics *Metrics, value float64) { metrics.AvgLatency = value }},
	}

	reThreads := regexp.MustCompile(`Number of threads: (\d+)`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		if match := reThreads.FindStringSubmatch(line); match != nil {
			threads, _ := strconv.Atoi(match[1])
			result.Results[threads] = Metrics{}
		}

		for _, pattern := range metricPatterns {
			if match := pattern.Regex.FindStringSubmatch(line); match != nil {
				value, _ := strconv.ParseFloat(match[1], 64)
				for thread := range result.Results {
					metrics := result.Results[thread]
					pattern.Field(&metrics, value)
					result.Results[thread] = metrics
				}
			}
		}
	}

	if scanner.Err() != nil {
		return BenchmarkResult{}, fmt.Errorf("读取文件时出错: %v", scanner.Err())
	}
	return result, nil
}

// 通用metris的打印函数
func PrintResults(results []BenchmarkResult, threads []int, metricName string) {
	fmt.Print(metricName + ":thread\t")
	for _, result := range results {
		fmt.Printf("%s\t", result.MachineType)
	}
	fmt.Println()
	for _, thread := range threads {
		fmt.Printf("%d\t", thread)
		for _, result := range results {
			metrics, ok := result.Results[thread]
			if ok {
				switch metricName {
				case "tps":
					fmt.Printf("%.1f\t", metrics.TPS)
				case "qps":
					fmt.Printf("%.1f\t", metrics.QPS)
				case "p95_latency":
					fmt.Printf("%.1f\t", metrics.P95Latency)
				case "avg_latency":
					fmt.Printf("%.1f\t", metrics.AvgLatency)
				default:
					fmt.Print("N/A\t")
				}
			} else {
				fmt.Print("N/A\t")
			}
		}
		fmt.Println()
	}
}
