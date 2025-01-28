package splog

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

type CustomFormatter struct {
	log.TextFormatter
}

func (f *CustomFormatter) Format(entry *log.Entry) ([]byte, error) {
	var levelColor string
	switch entry.Level {
	case log.InfoLevel:
		levelColor = "\033[0m" // 默认
		//levelColor = "\033[1;34m" // 蓝色
	case log.WarnLevel:
		levelColor = "\033[1;33m" // 黄色
	case log.ErrorLevel:
		levelColor = "\033[0;31m" // 普通红色
	case log.FatalLevel:
		levelColor = "\033[1;31m" // 加粗红色
	case log.DebugLevel:
		levelColor = "\033[1;36m" // 青色
	default:
		levelColor = "\033[0m" // 默认
	}

	// 特殊字段着色逻辑
	for key, value := range entry.Data {
		if key == "successField" {
			greenColor := "\033[1;32m"
			resetColor := "\033[0m"
			entry.Data[key] = fmt.Sprintf("%s%s%s", greenColor, value, resetColor)
		}
		if key == "failField" {
			redColor := "\033[0;31m"
			resetColor := "\033[0m"
			entry.Data[key] = fmt.Sprintf("%s%s%s", redColor, value, resetColor)
		}
		if key == "processingFiled" {
			blueColor := "\033[1;34m"
			resetColor := "\033[0m"
			entry.Data[key] = fmt.Sprintf("%s%s%s", blueColor, value, resetColor)
		}
	}

	entry.Message = fmt.Sprintf("%s%s\033[0m", levelColor, entry.Message)
	return f.TextFormatter.Format(entry)
}

func GreenInfof(format string, args ...interface{}) {
	// 使用 Infof 打印并加上绿色的转义字符
	log.Infof("\033[1;32m"+format+"\033[0m", args...)
}
