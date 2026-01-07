package utils

import (
	"fmt"
	"log"
)

// Info logs a message with the [INFO] prefix
func Info(v ...any) {
	log.Output(2, "[INFO] "+fmt.Sprintln(v...))
}

// Infof logs a formatted message with the [INFO] prefix
func Infof(format string, v ...any) {
	log.Output(2, "[INFO] "+fmt.Sprintf(format, v...))
}

// Error logs a message with the [ERROR] prefix
func Error(v ...any) {
	log.Output(2, "[ERROR] "+fmt.Sprintln(v...))
}

// Errorf logs a formatted message with the [ERROR] prefix
func Errorf(format string, v ...any) {
	log.Output(2, "[ERROR] "+fmt.Sprintf(format, v...))
}
