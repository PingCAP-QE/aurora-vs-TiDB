package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
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
	baseName := filepath.Base(filePath)
	reFileName := regexp.MustCompile(`^(.*?)-(.*?)\.log$`)
	match := reFileName.FindStringSubmatch(baseName)
	if match == nil || len(match) < 3 {
		return BenchmarkResult{}, fmt.Errorf("invalid file name format: %s", filePath)
	}
	machineType, testType := match[1], match[2]
	log.Infof("machine-type:%s, test-tyep:%s", machineType, testType)

	result := BenchmarkResult{
		MachineType: machineType,
		TestType:    testType,
		Results:     make(map[int]Metrics),
	}

	// 正则匹配逻辑，如果要其他指标请在这里添加
	metricPatterns := []MetricPattern{
		{"tps", regexp.MustCompile(`transactions:\s+[\d]+\s+\(([\d\.]+) per sec\.\)`), func(metrics *Metrics, value float64) { metrics.TPS = value }},
		{"qps", regexp.MustCompile(`queries:\s+[\d]+\s+\(([\d\.]+) per sec\.\)`), func(metrics *Metrics, value float64) { metrics.QPS = value }},
		{"p95_latency", regexp.MustCompile(`95th percentile: +([\d.]+)`), func(metrics *Metrics, value float64) { metrics.P95Latency = value }},
		{"avg_latency", regexp.MustCompile(`avg: +([\d.]+)`), func(metrics *Metrics, value float64) { metrics.AvgLatency = value }},
	}

	reThreads := regexp.MustCompile(`Number of threads: (\d+)`)

	scanner := bufio.NewScanner(file)
	var curThreads int
	for scanner.Scan() {
		line := scanner.Text()

		if match := reThreads.FindStringSubmatch(line); match != nil {
			curThreads, _ = strconv.Atoi(match[1])
			log.Debugf("Current threads: %d", curThreads)
			result.Results[curThreads] = Metrics{}
		}

		for _, pattern := range metricPatterns {
			if match := pattern.Regex.FindStringSubmatch(line); match != nil {
				value, _ := strconv.ParseFloat(match[1], 64)
				log.Debugf("%f", value)
				if curThreads != 0 {
					metrics := result.Results[curThreads]
					pattern.Field(&metrics, value)
					result.Results[curThreads] = metrics
				}
				log.Debugf("%v", result)
			}
		}
	}

	if scanner.Err() != nil {
		return BenchmarkResult{}, fmt.Errorf("error while read file: %v", scanner.Err())
	}
	return result, nil
}

// 通用metrics的打印函数
func PrintResults(results []BenchmarkResult, metricName, testType string) {
	fmt.Print("-----------------------------------------------------------------------------------------------\n")
	fmt.Printf("Aurora Performance Test Result Summary (%s)  ######  %s\n", testType, strings.ToUpper(metricName))
	fmt.Print("-----------------------------------------------------------------------------------------------\n")
	fmt.Print("Threads\t")
	for _, result := range results {
		fmt.Printf("%s\t", result.MachineType)
	}
	fmt.Println()

	// 获取所有线程号并打印，从所有 BenchmarkResult 中的 Results 字段获取线程列表
	threadSet := make(map[int]struct{})
	for _, result := range results {
		for thread := range result.Results {
			threadSet[thread] = struct{}{}
		}
	}

	// 转换线程集合为切片并排序
	var threads []int
	for thread := range threadSet {
		threads = append(threads, thread)
	}
	sort.Ints(threads)

	// 打印线程号行
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
	fmt.Print("-----------------------------------------------------------------------------------------------\n")
}

// ParseAndPrintResults 解析目录中的日志文件并按不同测试类型打印结果
func ParseAndPrintAllResults(dirPath string) error {
	// 获取目录下所有文件
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("Failed to read directory %s: %v", dirPath, err)
	}

	// 创建三个切片来存放不同类型的BenchmarkResult
	var oltpReadOnlyResults []BenchmarkResult
	var writeOnlyResults []BenchmarkResult
	var readWriteResults []BenchmarkResult

	// 遍历文件列表
	for _, file := range files {
		if file.IsDir() {
			continue // 跳过目录
		}

		// 根据文件名的模式来解析文件类型
		baseName := file.Name()
		var testType string
		re := regexp.MustCompile(`-(oltp_read_only|write_only|read_write)\.log$`)
		match := re.FindStringSubmatch(baseName)
		if match == nil || len(match) < 2 {
			log.Printf("Skipping file with invalid format: %s", baseName)
			continue
		}
		testType = match[1]

		// 解析文件
		rst, err := ParseBenchmarkLog(filepath.Join(dirPath, baseName))
		if err != nil {
			log.Errorf("Failed to parse log file %s: %v", baseName, err)
			continue
		}
		// 根据不同的testType将结果存储到对应的切片
		switch testType {
		case "oltp_read_only":
			oltpReadOnlyResults = append(oltpReadOnlyResults, rst)
		case "oltp_write_only":
			writeOnlyResults = append(writeOnlyResults, rst)
		case "oltp_read_write":
			readWriteResults = append(readWriteResults, rst)
		}
	}

	// 打印每个类型的结果
	metricNames := []string{"tps", "qps", "p95_latency", "avg_latency"}
	for _, metricName := range metricNames {
		PrintResults(oltpReadOnlyResults, metricName, "oltp_read_only")
		//PrintResults(writeOnlyResults, metricName, "write_only")
		//PrintResults(readWriteResults, metricName, "read_write")
	}

	return nil
}
