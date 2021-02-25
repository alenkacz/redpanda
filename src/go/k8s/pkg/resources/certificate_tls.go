package resources

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	certv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	redpandav1alpha1 "github.com/vectorizedio/redpanda/src/go/k8s/apis/redpanda/v1alpha1"
	"github.com/vectorizedio/redpanda/src/go/k8s/pkg/labels"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// SelfSignedIssuer is issuer used to generate tls certificates
type SelfSignedIssuer struct {
	k8sclient.Client
	scheme       *runtime.Scheme
	pandaCluster *redpandav1alpha1.Cluster
	logger       logr.Logger
}

// NewSelfSignedIssuer creates SelfSignedIssuer
func NewSelfSignedIssuer(
	client k8sclient.Client,
	pandaCluster *redpandav1alpha1.Cluster,
	scheme *runtime.Scheme,
	logger logr.Logger,
) *SelfSignedIssuer {
	return &SelfSignedIssuer{
		client, scheme, pandaCluster, logger.WithValues("Kind", serviceKind()),
	}
}

// Ensure will manage cert-manager v1.ClusterIssuer for TLS certificates
//nolint:dupl // we expect this to not be duplicated when more logic is added
func (i *SelfSignedIssuer) Ensure(ctx context.Context) error {
	var ci certv1.Issuer

	err := i.Get(ctx, i.Key(), &ci)
	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	if errors.IsNotFound(err) {
		i.logger.Info(fmt.Sprintf("Issuer %s does not exist, going to create one", i.Key().Name))

		obj, err := i.Obj()
		if err != nil {
			return err
		}

		return i.Create(ctx, obj)
	}

	return nil
}

func (i *SelfSignedIssuer) Obj() (k8sclient.Object, error) {
	objLabels := labels.ForCluster(i.pandaCluster)

	cert := &certv1.Issuer{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: i.Key().Namespace,
			Name:      i.Key().Name,
			Labels:    objLabels,
		},
		Spec: certv1.IssuerSpec{
			IssuerConfig: certv1.IssuerConfig{
				SelfSigned: &certv1.SelfSignedIssuer{},
			},
		},
	}
	err := controllerutil.SetControllerReference(i.pandaCluster, cert, i.scheme)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (i *SelfSignedIssuer) Key() types.NamespacedName {
	return types.NamespacedName{Name: fmt.Sprintf("%s-self-signed", i.pandaCluster.Name), Namespace: i.pandaCluster.Namespace}
}

func (r *SelfSignedIssuer) Kind() string {
	var ssi certv1.Issuer
	return ssi.Kind
}
