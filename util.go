package main

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	ResourceTypeAuroraCluster   = "Aurora-Cluster"
	ResourceTypeAuroraInstance  = "Aurora-Instance"
	ResourceTypeAuroraParameter = "Aurora-Parameter-Group"
	ResourceTypeEC2Instance     = "EC2-Instance"
	ResourceTypeVPCInstance     = "VPC-Instance"
)

// 定义检查状态的函数类型
type StatusChecker func(resourceID string) (string, error)

// PollResourceStatus 轮询资源状态直到达到目标状态或超时
func PollResourceStatus(resourceID, resourceType, targetStatus string, timeout time.Duration, checkStatusFunc StatusChecker) error {
	startTime := time.Now()
	retries := 1
	//api 与 action-resp 异步操作
	time.Sleep(10 * time.Second)

	for {
		// 检查资源状态
		currentStatus, err := checkStatusFunc(resourceID)
		if err != nil {
			log.WithFields(log.Fields{
				"resource": resourceID,
			}).Errorf("Error checking status: %v", err)
			return fmt.Errorf("error checking status for resource %s: %v", resourceID, err)
		}

		// 输出状态信息
		log.WithFields(log.Fields{
			"total-cycle": retries,
			"resource":    resourceID,
			"status":      currentStatus,
			"type":        resourceType,
		}).Info("Checking resource status")

		// 检查是否达成目标状态
		if currentStatus == targetStatus {
			duration := time.Since(startTime)
			GreenInfof("%s %s reached to status %s, total cost time: %v", resourceType, resourceID, targetStatus, duration)
			return nil
		}

		// 检查是否超时
		if time.Since(startTime) > timeout {
			log.WithFields(log.Fields{
				"resource": resourceID,
				"timeout":  timeout,
			}).Warn("Polling timed out")
			return fmt.Errorf("polling for resource %s timed out after %s: current-state %s, expected-state %s", resourceID, timeout, currentStatus, targetStatus)
		}

		retries++
		time.Sleep(30 * time.Second)
	}
}
