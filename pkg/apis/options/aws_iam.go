package options

type AWSIAMConfig struct {
	// AWS service redis service being used. "elasticache" or "memorydb"
	ServiceName         string   `json:"serviceName,omitempty`
	// AWS Cluster name
	ClusterName         string   `json:"clusterName,omitempty`
	// AWS Username
	Username            string   `json:"userName,omitempty`
}
