// Copyright 2021 Vectorized, Inc.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.md
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0

package v1alpha1

import (
	"fmt"

	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterSpec defines the desired state of Cluster
type ClusterSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Image is the fully qualified name of the Redpanda container
	Image string `json:"image,omitempty"`
	// Version is the Redpanda container tag
	Version string `json:"version,omitempty"`
	// Replicas determine how big the cluster will be.
	// +kubebuilder:validation:Minimum=0
	Replicas *int32 `json:"replicas,omitempty"`
	// Resources used by each Redpanda container
	// To calculate overall resource consumption one need to
	// multiply replicas against limits
	Resources corev1.ResourceRequirements `json:"resources"`
	// Configuration represent redpanda specific configuration
	Configuration RedpandaConfig `json:"configuration,omitempty"`
	// If specified, Redpanda Pod tolerations
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
	// If specified, Redpanda Pod node selectors. For reference please visit
	// https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// ExternalConnectivity enables user to expose Redpanda
	// nodes outside of a Kubernetes cluster. For more
	// information please go to ExternalConnectivityConfig
	ExternalConnectivity ExternalConnectivityConfig `json:"externalConnectivity,omitempty"`
	// Storage spec for cluster
	Storage StorageSpec `json:"storage,omitempty"`
	// Cloud storage configuration for cluster
	CloudStorage CloudStorageConfig `json:"cloudStorage,omitempty"`
	// Enable and configure pandaproxy
	PandaProxy PandaProxyConfig `json:"pandaProxy,omitempty"`
}

// PandaProxyConfig enables and configures pandaproxy
type PandaProxyConfig struct {
	// if set to true, pandaproxy will be enabled
	Enabled bool `json:"enabled,omitempty"`
	// port for internal communication using pandaproxy
	Port SocketAddress `json:"port,omitempty"`
	// when enabled, pandaproxy will be reachable from outside of the cluster.
	// Port + 1 will be used as port for external communication.
	ExternalConnectivity ExternalConnectivityConfig `json:"externalConnectivity,omitempty"`
	// If enabled, communication with pandaproxy over specified port will happen
	// only via TLS
	TLS TLSConfig `json:"tls,omitempty"`
}

// CloudStorageConfig configures the Data Archiving feature in Redpanda
// https://vectorized.io/docs/data-archiving
type CloudStorageConfig struct {
	// Enables data archiving feature
	Enabled bool `json:"enabled"`
	// Cloud storage access key
	AccessKey string `json:"accessKey,omitempty"`
	// Reference to (Kubernetes) Secret containing the cloud storage secret key.
	// SecretKeyRef must contain the name and namespace of the Secret.
	// The Secret must contain a data entry of the form:
	// data[<SecretKeyRef.Name>] = <secret key>
	SecretKeyRef corev1.ObjectReference `json:"secretKeyRef,omitempty"`
	// Cloud storage region
	Region string `json:"region,omitempty"`
	// Cloud storage bucket
	Bucket string `json:"bucket,omitempty"`
	// Reconciliation period (default - 10s)
	ReconcilicationIntervalMs int `json:"reconciliationIntervalMs,omitempty"`
	// Number of simultaneous uploads per shard (default - 20)
	MaxConnections int `json:"maxConnections,omitempty"`
	// Disable TLS (can be used in tests)
	DisableTLS bool `json:"disableTLS,omitempty"`
	// Path to certificate that should be used to validate server certificate
	Trustfile string `json:"trustfile,omitempty"`
	// API endpoint for data storage
	APIEndpoint string `json:"apiEndpoint,omitempty"`
	// Used to override TLS port (443)
	APIEndpointPort int `json:"apiEndpointPort,omitempty"`
}

// StorageSpec defines the storage specification of the Cluster
type StorageSpec struct {
	// Storage capacity requested
	Capacity resource.Quantity `json:"capacity,omitempty"`
	// Storage class name - https://kubernetes.io/docs/concepts/storage/storage-classes/
	StorageClassName string `json:"storageClassName,omitempty"`
}

// ExternalConnectivityConfig adds listener that can be reached outside
// of a kubernetes cluster. The Service type NodePort will be used
// to create unique ports on each Kubernetes nodes. Those nodes
// need to be reachable from the client perspective. Setting up
// any additional resources in cloud or premise is the responsibility
// of the Redpanda operator user e.g. allow to reach the nodes by
// creating new rule in AWS security group.
// Inside the container the Configuration.KafkaAPI.Port + 1 will be
// used as a external listener. This port is tight to the autogenerated
// host port. The collision between Kafka external, Kafka internal,
// Admin and RPC port is checked in the webhook.
type ExternalConnectivityConfig struct {
	// Enabled enables the external connectivity feature
	Enabled bool `json:"enabled,omitempty"`
	// Subdomain can be used to change the behavior of an advertised
	// KafkaAPI. Each broker advertises Kafka API as follows
	// HOSTNAME_OF_A_POD.SUBDOMAIN:EXTERNAL_KAFKA_API_PORT.
	// If Subdomain is empty then each broker advertises Kafka
	// API as PUBLIC_NODE_IP:EXTERNAL_KAFKA_API_PORT.
	// If TLS is enabled then this subdomain will be requested
	// as a subject alternative name.
	Subdomain string `json:"subdomain,omitempty"`
}

// ClusterStatus defines the observed state of Cluster
type ClusterStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Replicas show how many nodes are working in the cluster
	// +optional
	Replicas int32 `json:"replicas"`
	// Nodes of the provisioned redpanda nodes
	// +optional
	Nodes NodesList `json:"nodes,omitempty"`
	// Indicates cluster is upgrading
	// +optional
	Upgrading bool `json:"upgrading"`
}

// NodesList shows where client can find Redpanda brokers
type NodesList struct {
	Internal []string `json:"internal,omitempty"`
	External []string `json:"external,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Cluster is the Schema for the clusters API
type Cluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterSpec   `json:"spec,omitempty"`
	Status ClusterStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ClusterList contains a list of Cluster
type ClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Cluster `json:"items"`
}

// RedpandaConfig is the definition of the main configuration
type RedpandaConfig struct {
	RPCServer     SocketAddress `json:"rpcServer,omitempty"`
	KafkaAPI      SocketAddress `json:"kafkaApi,omitempty"`
	AdminAPI      SocketAddress `json:"admin,omitempty"`
	DeveloperMode bool          `json:"developerMode,omitempty"`
	TLS           TLSConfigs    `json:"tls,omitempty"`
}

// TLSConfigs configures TLS for Redpanda APIs
type TLSConfigs struct {
	// Configuration of TLS for Kafka API
	KafkaAPI TLSConfig `json:"kafkaApi,omitempty"`
	// Configuration of TLS for Admin API
	AdminAPI AdminAPITLS `json:"adminApi,omitempty"`
}

// TLSConfig configures TLS for redpanda listener
//
// If Enabled is set to true, one-way TLS verification is enabled.
// In that case, a key pair ('tls.crt', 'tls.key') and CA certificate 'ca.crt'
// are generated and stored in a Secret with the same name and namespace as the
// Redpanda cluster. 'ca.crt', must be used by a client as a trustore when
// communicating with Redpanda.
//
// If RequireClientAuth is set to true, two-way TLS verification is enabled.
// In that case, a node and three client certificates are created.
// The node certificate is used by redpanda nodes.
//
// The three client certificates are the following: 1. operator client
// certificate is for internal use of this kubernetes operator 2. admin client
// certificate is meant to be used by your internal infrastructure, other than
// operator. It's possible that you might not need this client certificate in
// your setup. The client certificate can be retrieved from the Secret named
// '<redpanda-cluster-name>-admin-client'. 3. user client certificate is
// available for Redpanda users to call redpanda api. The client certificate can be
// retrieved from the Secret named '<redpanda-cluster-name>-user-client'.
//
// All TLS secrets are stored in the same namespace as the Redpanda cluster.
type TLSConfig struct {
	Enabled bool `json:"enabled,omitempty"`
	// References cert-manager Issuer or ClusterIssuer. When provided, this
	// issuer will be used to issue node certificates.
	// Typically you want to provide the issuer when a generated self-signed one
	// is not enough and you need to have a verifiable chain with a proper CA
	// certificate.
	IssuerRef *cmmeta.ObjectReference `json:"issuerRef,omitempty"`
	// If provided, operator uses certificate in this secret instead of
	// issuing its own node certificate. The secret is expected to provide
	// the following keys: 'ca.crt', 'tls.key' and 'tls.crt'
	// If NodeSecretRef points to secret in different namespace, operator will
	// duplicate the secret to the same namespace as redpanda CRD to be able to
	// mount it to the nodes
	NodeSecretRef *corev1.ObjectReference `json:"nodeSecretRef,omitempty"`
	// Enables two-way verification on the server side. If enabled, all Kafka
	// API clients are required to have a valid client certificate.
	RequireClientAuth bool `json:"requireClientAuth,omitempty"`
}

// AdminAPITLS configures TLS for Redpanda Admin API
//
// If Enabled is set to true, one-way TLS verification is enabled.
// In that case, a key pair ('tls.crt', 'tls.key') and CA certificate 'ca.crt'
// are generated and stored in a Secret with the same name and namespace as the
// Redpanda cluster. 'ca.crt' must be used by a client as a truststore when
// communicating with Redpanda.
//
// If RequireClientAuth is set to true, two-way TLS verification is enabled.
// In that case, a client certificate is generated, which can be retrieved from
// the Secret named '<redpanda-cluster-name>-admin-api-client'.
//
// All TLS secrets are stored in the same namespace as the Redpanda cluster.
type AdminAPITLS struct {
	Enabled           bool `json:"enabled,omitempty"`
	RequireClientAuth bool `json:"requireClientAuth,omitempty"`
}

// SocketAddress provide the way to configure the port
type SocketAddress struct {
	Port int `json:"port,omitempty"`
}

func init() {
	SchemeBuilder.Register(&Cluster{}, &ClusterList{})
}

// FullImageName returns image name including version
func (r *Cluster) FullImageName() string {
	return fmt.Sprintf("%s:%s", r.Spec.Image, r.Spec.Version)
}
