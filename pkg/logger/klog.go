package logger

// KlogInfoLogger is used for info level log output in Klog
type KlogInfoLogger struct {
	logger *Logger
}

// Write is used to output klog log lines
func (l *KlogInfoLogger) Write(data []byte) (int, error) {
	l.logger.Output(DEFAULT, 6, string(data))
	return len(data), nil
}

// KlogInfoLogger is used for error level log output in Klog
type KlogErrorLogger struct {
	logger *Logger
}

// Write is used to output klog log lines
func (l *KlogErrorLogger) Write(data []byte) (int, error) {
	l.logger.Output(ERROR, 6, string(data))
	return len(data), nil
}

// StdKlogInfoLogger is an info logger using the standard logger
var StdKlogInfoLogger = &KlogInfoLogger{logger: std}

// StdKlogErrorLogger is an info logger using the standard logger
var StdKlogErrorLogger = &KlogErrorLogger{logger: std}
