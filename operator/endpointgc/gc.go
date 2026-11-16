// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointgc

import (
	"context"
	"log/slog"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// params contains all the dependencies for the endpoint-gc.
// They will be provided through dependency injection.
type params struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	JG        job.Group

	Clientset       k8sClient.Clientset
	CiliumEndpoints resource.Resource[*cilium_api_v2.CiliumEndpoint]
	Pods            resource.Resource[*slim_corev1.Pod]

	Cfg       Config
	SharedCfg SharedConfig

	Metrics *Metrics
}

// GC represents the Cilium endpoints periodic and one-off GC.
type GC struct {
	logger *slog.Logger

	interval time.Duration

	clientset       k8sClient.Clientset
	ciliumEndpoints resource.Resource[*cilium_api_v2.CiliumEndpoint]
	pods            resource.Resource[*slim_corev1.Pod]

	pending  map[resource.Key]staleCheckResult
	cepStore resource.Store[*cilium_api_v2.CiliumEndpoint]
	podStore resource.Store[*slim_corev1.Pod]

	metrics *Metrics
}

func registerGC(p params) {
	if !p.Clientset.IsEnabled() {
		return
	}
	if p.Cfg.CiliumEndpointGCInterval <= 0 {
		return
	}

	gc := &GC{
		logger:          p.Logger,
		interval:        p.Cfg.CiliumEndpointGCInterval,
		clientset:       p.Clientset,
		ciliumEndpoints: p.CiliumEndpoints,
		pods:            p.Pods,
		metrics:         p.Metrics,
		pending:         map[resource.Key]staleCheckResult{},
	}

	// if CEP has been disabled, remove all stale CEPs
	if p.SharedCfg.DisableCiliumEndpointCRD {
		p.JG.Add(job.OneShot(
			"cilium-endpoint-cleanup",
			gc.doCleanup,
			job.WithRetry(10, &job.ExponentialBackoff{
				Min: p.Cfg.CiliumEndpointGCInterval,
				Max: 10 * p.Cfg.CiliumEndpointGCInterval,
			})))
	} else if p.Cfg.CiliumEndpointGCInterval > 0 {
		p.JG.Add(job.Timer("cilium-endpoint-gc", gc.doGC, p.Cfg.CiliumEndpointGCInterval))
	}
}

const maxRetries = 10

// CheckForCiliumEndpointCRD returns true if the CEP CRD exists in the apiserver.
func CheckForCiliumEndpointCRD(ctx context.Context, clientset k8sClient.Clientset, logger *slog.Logger) (bool, error) {
	bo := wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   1.1,
		Jitter:   0.1,
		Steps:    maxRetries,
	}

	exists := false

	err := wait.ExponentialBackoffWithContext(ctx, bo, func(ctx context.Context) (bool, error) {
		_, getErr := clientset.ApiextensionsV1().CustomResourceDefinitions().Get(
			ctx, cilium_api_v2.CEPName, metav1.GetOptions{ResourceVersion: "0"},
		)
		if getErr == nil {
			exists = true
			return true, nil
		} else if k8serrors.IsNotFound(getErr) {
			exists = false
			return true, nil // return true: condition is satisfied
		} else {
			logger.ErrorContext(ctx, "Could not retrieve CiliumEndpoint CRD. Will retry.",
				logfields.Error, getErr,
				logfields.Name, cilium_api_v2.CEPName)
			return false, nil // don't return error;
		}
	})

	return exists, err
}

// doCleanup deletes all existing CiliumEndpoints.
// This is used when CiliumEndpoint is being disabled (e.g. when policy is disabled)
func (g *GC) doCleanup(ctx context.Context, health cell.Health) error {
	crdExists, err := CheckForCiliumEndpointCRD(ctx, g.clientset, g.logger)
	if err != nil {
		return err
	}
	if !crdExists {
		g.logger.InfoContext(ctx, "CiliumEndpoint CRD cannot be found, skipping cleanup", logfields.Error, err)
		return nil
	}

	cepStore, err := g.ciliumEndpoints.Store(ctx)
	if err != nil {
		g.logger.ErrorContext(ctx, "Couldn't get CEP Store", logfields.Error, err)
		return err
	}

	g.logger.Info("CiliumEndpoint is disabled, deleting all remaining instances")

	count := 0
	iter := cepStore.IterKeys()
	for iter.Next() {
		key := iter.Key()
		scopedLog := g.logger.With(
			logfields.K8sNamespace, key.Namespace,
			logfields.CEPName, key.Name,
		)

		if err := g.deleteCEP(ctx, key.Namespace, key.Name, nil, scopedLog); err != nil && !k8serrors.IsNotFound(err) {
			return err
		}
		count++
	}

	if count > 0 {
		g.logger.Info("CiliumEndpoint is disabled, deleted stale CiliumEndpoint instances",
			logfields.Count, count)
	}
	return nil
}

// doGC runs the CEP GC loop.
//
// It looks for CEPs that do not match their pods. If they stay stale
// for 2 cycles, they are deleted on the second cycle.
//
// This is safe to do, because the owning agent will re-create the CEP
// if it goes missing.
func (g *GC) doGC(ctx context.Context) error {
	g.logger.InfoContext(ctx, "Starting to garbage collect stale CiliumEndpoint custom resources")

	if g.cepStore == nil {
		var err error
		g.cepStore, err = g.ciliumEndpoints.Store(ctx)
		if err != nil {
			g.logger.ErrorContext(ctx, "Couldn't get CEP Store", logfields.Error, err)
			return err
		}
	}

	if g.podStore == nil {
		var err error
		g.podStore, err = g.pods.Store(ctx)
		if err != nil {
			g.logger.ErrorContext(ctx, "Couldn't get Pod store", logfields.Error, err)
			return err
		}
	}

	count := 0
	oldPending := g.pending
	g.pending = make(map[resource.Key]staleCheckResult)

	iter := g.cepStore.IterKeys()
	for iter.Next() {
		key := iter.Key()
		cep, exists, err := g.cepStore.GetByKey(key)
		if err != nil {
			return err // not reachable, GetByKey never returns error
		}
		if !exists {
			continue
		}

		scopedLog := g.logger.With(
			logfields.K8sNamespace, key.Namespace,
			logfields.CEPName, key.Name,
		)

		// Determine the staleness of the CEP
		res, err := g.isStale(cep, scopedLog)
		if err != nil {
			scopedLog.Warn("Failed to check for pod staleness", logfields.Error, err)
			continue
		}
		if !res.isStale() {
			continue
		}

		// we cannot delete stale CEPs immediately, as we might have gotten the CEP
		// update before the Pod (although unlikely). So, we require CEPs
		// to be stale for two cycles before deletion
		oldRes, ok := oldPending[key]
		// If this CEP was already marked as stale for the same reason, we can delete it
		if ok && oldRes == res {
			scopedLog.Info("Deleting stale CiliumEndpoint", logfields.Reason, res.describe())
			err := g.deleteCEP(ctx, key.Namespace, key.Name, cep, scopedLog)
			if err != nil {
				// deletion failed; save stale state
				g.pending[key] = res
			} else {
				count++
			}
		} else {
			g.pending[key] = res
		}

	}
	if count > 0 {
		g.logger.Info("Deleted stale CiliumEndpoints", logfields.Count, count)
	}

	return nil
}

// inverted conditions to make the zero value mean no action is required
type staleCheckResult struct {
	// no owner is set
	orphaned bool

	// donePod means the pod exists but is not running
	donePod bool

	// wrongNode means the pod's scheduled node and CEP node don't match
	wrongNode string
}

func (dcr staleCheckResult) isStale() bool {
	return dcr != staleCheckResult{}
}

func (dcr staleCheckResult) describe() string {
	if dcr.orphaned {
		return "no owner reference"
	}
	if dcr.donePod {
		return "pod is in state Failed or Succeeded"
	}
	if dcr.wrongNode != "" {
		return "CEP node does not match pod node"
	}
	return ""
}

// isStale checks if the given CEP is stale.
//
// A CEP is stale if:
// - It has no owner references
// - It is owned by a pod that is Finished
// - It is owned by a Pod that is scheduled to a different node
//
// Deleting finished-job endpoints is an optimization to reduce ipcache load for
// pods that will never run again.
func (g *GC) isStale(cep *cilium_api_v2.CiliumEndpoint, scopedLog *slog.Logger) (staleCheckResult, error) {
	// In rare cases when ciliumendpoint is too new, and we haven't received pod
	// notifications, we might delete this ciliumendpoint unexpectedly. Whie we
	// are still prone to the cache delay if g.interval is too small or when the
	// watch cache for pods has an arbitrary delay, the chance is much lower than
	// it is today.
	const informerSyncGracePeriod = 10 * time.Second
	if time.Since(cep.CreationTimestamp.Time) < informerSyncGracePeriod {
		return staleCheckResult{}, nil
	}

	// Endpoints without an Owner means that someone did `kubectl delete --cascade=orphan`,
	// which removes OwnerReferences from dependent objects.
	//
	// This CEP should be deleted.
	if len(cep.OwnerReferences) == 0 {
		return staleCheckResult{orphaned: true}, nil
	}

	// Look up all owners. If they are Pods, check to see
	// that they are valid (running and correct node)
	for _, owner := range cep.OwnerReferences {
		if owner.APIVersion != "v1" || owner.Kind != "Pod" {
			g.logger.Debug("Skipping staleness checks for non-Pod CiliumEndpoint")
			continue
		}

		pod, _, err := g.podStore.GetByKey(resource.Key{
			Namespace: cep.Namespace,
			Name:      owner.Name,
		})
		if err != nil {
			// not reachable, GetByKey never returns error
			g.logger.Warn("BUG: Pod lookup failed", logfields.Error, err)
			return staleCheckResult{}, nil
		}

		// If the UIDs do not match, it means the pod is being deleted
		// and we can ignore it. It is not possible to have a CEP with
		// a dangling owner reference.
		if pod == nil || pod.UID != owner.UID {
			g.logger.Debug("Could not find referenced pod (possibly stale informer), ignoring")

			continue
		}

		// Is the pod valid?
		// In Kubernetes Jobs, Pods can be left in Kubernetes until the Job
		// is deleted. If the Job is never deleted, Cilium will never receive a Pod
		// delete event, causing the IP to be left in the ipcache.
		// For this reason we should delete the ipcache entries whenever the pod
		// status is either PodFailed or PodSucceeded as it means the IP address
		// is no longer in use.
		if !k8sUtils.IsPodRunning(pod.Status) {
			return staleCheckResult{
				donePod: true,
			}, nil
		}

		// Check that the EP's node matches the CEP's node.
		// cep.Status.NodeName was added in v1.21, so we must also tolerate blank values.
		if cep.Status.NodeName != "" && cep.Status.NodeName != pod.Spec.NodeName {
			return staleCheckResult{
				wrongNode: pod.Spec.NodeName,
			}, nil
		}
	}

	return staleCheckResult{}, nil
}

// deleteCEP deletes the given CliliumEndpoint. If an existing CEP is provided, its resource version
// and UID is used as a deletion precondition to ensure we don't conflict.
func (g *GC) deleteCEP(ctx context.Context, namespace, name string, existingCEP *cilium_api_v2.CiliumEndpoint, scopedLog *slog.Logger) error {
	scopedLog.DebugContext(ctx, "Deleting stale or orphaned CiliumEndpoint")

	deleteOpts := metav1.DeleteOptions{
		PropagationPolicy: new(metav1.DeletePropagationBackground),
	}
	if existingCEP != nil {
		// Set precondition to ensure we are only deleting CEPs owned by
		// this agent.
		deleteOpts.Preconditions = &metav1.Preconditions{
			UID:             &existingCEP.UID,
			ResourceVersion: &existingCEP.ResourceVersion,
		}
	}

	err := g.clientset.CiliumV2().CiliumEndpoints(namespace).Delete(
		ctx,
		name,
		deleteOpts,
	)
	switch {
	case err == nil:
		g.metrics.EndpointGCObjects.WithLabelValues(LabelValueOutcomeSuccess).Inc()
		return nil
	case k8serrors.IsNotFound(err):
		return nil // don't increment metric, but this is success
	case k8serrors.IsConflict(err):
		scopedLog.DebugContext(ctx, "Unable to delete CEP, will retry", logfields.Error, err)
		g.metrics.EndpointGCObjects.WithLabelValues(LabelValueOutcomeFail).Inc()
		return err
	default:
		scopedLog.WarnContext(ctx, "Unable to delete orphaned CEP, will retry", logfields.Error, err)
		g.metrics.EndpointGCObjects.WithLabelValues(LabelValueOutcomeFail).Inc()
		return err
	}
}
