// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/stream"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// subsysEndpointSync is the value for logfields.LogSubsys
	subsysEndpointSync      = "endpointsynchronizer"
	informerSyncGracePeriod = 10 * time.Second
)

var ciliumEndpointToK8sSyncControllerGroup = controller.NewGroup("sync-to-k8s-ciliumendpoint")

type endpointSynchronizerParams struct {
	cell.In

	JG                  job.Group
	Clientset           client.Clientset
	CiliumEndpoint      resource.Resource[*k8sTypes.CiliumEndpoint]
	CiliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	LocalNodeStore      *node.LocalNodeStore
	EndpointManager     EndpointManager
}

func newEndpointSynchronizer(p endpointSynchronizerParams) *endpointSynchronizer {
	if !p.Clientset.IsEnabled() || option.Config.DisableCiliumEndpointCRD {
		return nil
	}

	epSync := &endpointSynchronizer{
		Clientset:           p.Clientset,
		CiliumEndpoint:      p.CiliumEndpoint,
		CiliumEndpointSlice: p.CiliumEndpointSlice,
		localNodeStore:      p.LocalNodeStore,
		EM:                  p.EndpointManager,

		q: make(chan *endpoint.Endpoint, 512),
	}

	if p.JG != nil {
		obs := stream.FromChannel(epSync.q)
		p.JG.Add(job.Observer("sync-to-k8s-ciliumendpoint", epSync.observeEPs, obs))
		p.JG.Add(job.Timer("periodic-k8s-ciliumendpoint-sync", epSync.periodicResync, informerSyncGracePeriod))
	}

	if p.EndpointManager != nil {
		p.EndpointManager.Subscribe(epSync)
	}

	return epSync
}

// endpointSynchronizer currently is an empty type, which wraps around syncing
// of CiliumEndpoint resources.
type endpointSynchronizer struct {
	Clientset           client.Clientset
	CiliumEndpoint      resource.Resource[*k8sTypes.CiliumEndpoint]
	CiliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	localNodeStore      *node.LocalNodeStore
	EM                  EndpointManager

	nodeName string

	// Queue of endpoints to update.
	q chan (*endpoint.Endpoint)

	epStore resource.Store[*k8sTypes.CiliumEndpoint]
}

// timer job that periodically enqueues all endpoints to be resynchronized
func (epSync *endpointSynchronizer) periodicResync(ctx context.Context) error {
	eps := epSync.EM.GetEndpoints()
	for _, ep := range eps {
		select {
		case epSync.q <- ep:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// implementation of endpointmanager.Subscriber

// Handle endpoint update events directly
func (epSync *endpointSynchronizer) EndpointCreated(e *endpoint.Endpoint) {
	select {
	case epSync.q <- e:
	default:
		// it's OK to drop this here; the periodic resync will catch it
	}
}

func (epSync *endpointSynchronizer) EndpointDeleted(e *endpoint.Endpoint, _ endpoint.DeleteConfig) {
	select {
	case epSync.q <- e:
	default:
		// we cannot drop delete events
		go func() {
			epSync.q <- e
		}()
	}
}

func (epSync *endpointSynchronizer) EndpointRestored(e *endpoint.Endpoint) {
	select {
	case epSync.q <- e:
	default:
		// it's OK to drop this here; the periodic resync will catch it
	}
}

func (epSync *endpointSynchronizer) observeEPs(ctx context.Context, e *endpoint.Endpoint) error {
	// initialize some one-off state.
	if epSync.nodeName == "" {
		ln, err := epSync.localNodeStore.Get(ctx)
		if err != nil {
			return err
		}
		epSync.nodeName = ln.Name
	}
	if epSync.epStore == nil {
		epStore, err := epSync.CiliumEndpoint.Store(ctx)
		if err != nil {
			return err
		}
		epSync.epStore = epStore
	}

	var (
		scopedLog = e.Logger(subsysEndpointSync)
		cepName   = e.GetK8sCEPName()
	)

	if cepName == "" {
		scopedLog.Debug("Skipping CiliumEndpoint update because it has no k8s cep name")
		return nil
	}
	scopedLog = scopedLog.With(logfields.CEPName, cepName)

	// If the EP is going away, delete it
	if !e.IsAlive() {
		err := epSync.deleteCEP(ctx, scopedLog, e)
		if err != nil {
			scopedLog.Warn("Failed to delete CiliumEndpoint (will retry)", logfields.Error, err)
			// Deletion failed! We *must* requeue, or we will leak CEPs
			// This could block, since we're in the handler function. In that case,
			// spawn a goroutine and continue
			select {
			case epSync.q <- e:
			default:
				go func() {
					epSync.q <- e
				}()
			}
		}
		return nil
	} else {
		// Otherwise, make sure the CEP is updated.
		err := epSync.doCiliumEndpointSync(ctx, e)
		if err != nil {
			scopedLog.Warn("CiliumEndpoint change failed (will retry)", logfields.Error, err)
		}
		// no need to explicitly requeue, this is an alive endpoint that will be re-synced
		return nil
	}
}

// doCiliumEndpointSync synchronizes the CiliumEndpoint object in the apiserver for this given endpoint.
func (epSync *endpointSynchronizer) doCiliumEndpointSync(ctx context.Context, e *endpoint.Endpoint) error {
	var (
		scopedLog = e.Logger(subsysEndpointSync)
		cepName   = e.GetK8sCEPName()
		ns        = e.GetK8sNamespace()
		owner     = e.GetCEPOwner()
	)

	if epSync.EM.LookupCEPName(ns+"/"+cepName) != e {
		// This could happen if we somehow handled a pod delete after creation,
		// but it really shouldn't happen.
		scopedLog.Debug("BUG: two endpoints have the same CiliumEndpoint name")
		return nil
	}

	if owner.IsNil() {
		scopedLog.Debug("Skipping CiliumEndpoint update because it has no owner")
		return nil
	}

	// Determine the existing CEP
	// (This is from the local store, so it may have some delay)
	existingSlimCEP, _, err := epSync.epStore.GetByKey(resource.Key{Namespace: ns, Name: cepName})
	if err != nil {
		// should not be reachable
		return fmt.Errorf("BUG: CEP local lookup failed: %w", err)
	}

	if existingSlimCEP == nil && e.GetCiliumEndpointUID() != "" {
		scopedLog.Warn("CEP was deleted externally or there is a significant delay on the CEP informer, will recreate")
	}

	// See if the desired CEP matches the existing SlimCEP.
	//
	// This is made more difficult by the fact that SlimCEP throws away some of the
	// fields we set.
	newCEP := makeCEP(e)
	if canSkipWrite(newCEP, existingSlimCEP) {
		// TODO: make this stochastic -- we should force an update randomly.
		scopedLog.Debug("Skipping CEP update (unchanged)")
		return nil
	}

	newCEP, err = epSync.ensureCEP(ctx, scopedLog, newCEP, existingSlimCEP == nil)
	if err != nil {
		return err
	} else {
		if e.SetCiliumEndpointUID(newCEP.UID) {
			e.SyncEndpointHeaderFile()
		}
	}
	return nil
}

func makeOwnerReferences(cepOwner endpoint.CEPOwnerInterface) meta_v1.OwnerReference {
	return meta_v1.OwnerReference{
		APIVersion: cepOwner.GetAPIVersion(),
		Kind:       cepOwner.GetKind(),
		Name:       cepOwner.GetName(),
		UID:        cepOwner.GetUID(),
	}
}

func makeCEP(e *endpoint.Endpoint) *cilium_v2.CiliumEndpoint {
	cepOwner := e.GetCEPOwner()
	cep := &cilium_v2.CiliumEndpoint{
		ObjectMeta: meta_v1.ObjectMeta{
			Namespace:       e.GetK8sNamespace(),
			Name:            e.GetK8sCEPName(),
			OwnerReferences: []meta_v1.OwnerReference{makeOwnerReferences(cepOwner)},
			// Mirror the labels of parent pod in CiliumEndpoint object to enable
			// label based selection for CiliumEndpoints.
			Labels: cepOwner.GetLabels(),
		},
		Status: *e.GetCiliumEndpointStatus(),
	}

	return cep
}

func canSkipWrite(newCEP *cilium_v2.CiliumEndpoint, existingSlimCEP *k8sTypes.CiliumEndpoint) bool {
	if existingSlimCEP != nil {
		// check to see if they're unchanged
		newSlimCEP, _ := k8s.TransformToCiliumEndpoint(newCEP)
		return newSlimCEP.DeepEqual(existingSlimCEP)
	}
	return false
}

// ensureCEP will create or update the desired CiliumEndpoint. It handles
// cases where the desired CEP does or does not exist unexpectedly.
func (epSync *endpointSynchronizer) ensureCEP(ctx context.Context, log *slog.Logger, newCEP *cilium_v2.CiliumEndpoint, tryCreate bool) (res *cilium_v2.CiliumEndpoint, err error) {
	if tryCreate {
		res, err = epSync.createCEP(ctx, newCEP)
		if err == nil {
			log.Info("created CiliumEndpoint")
			return
		} else {
			err = fmt.Errorf("failed to create CiliumEndpoint: %w", err)
		}
	} else {
		res, err = epSync.updateCEP(ctx, newCEP)
		if err == nil {
			log.Info("updated CiliumEndpoint")
			return
		} else {
			err = fmt.Errorf("failed to update CiliumEndpoint: %w", err)
		}
	}

	if tryCreate && k8serrors.IsAlreadyExists(err) {
		log.Info("CiliumEndpoint already exists, trying update")
		return epSync.ensureCEP(ctx, log, newCEP, !tryCreate)
	} else if !tryCreate && k8serrors.IsNotFound(err) {
		log.Info("CiliumEndpoint unexpectedly missing, will try creation")
		return epSync.ensureCEP(ctx, log, newCEP, !tryCreate)
	}
	return
}

// updateCEP updates the Status and Labels fields of a given CiliumEndpoint.
//
// This is done as a JSON patch with the condition that the owning resource matches
// our understanding of the owner. This is to prevent us from editing the CEP
// of a pod we don't own.
// Note that we **do not** check the ResourceVersion, as that's not relevant. The
// Status field is entirely owned by the agent.
// If there is a CEP referencing a stale pod, it will be deleted by the
// CEP GC loop in the operator.
func (epSync *endpointSynchronizer) updateCEP(ctx context.Context, newCEP *cilium_v2.CiliumEndpoint) (*cilium_v2.CiliumEndpoint, error) {
	patch := []k8s.JSONPatch{
		// Condition this update on us having the same owner as the existing CEP
		{
			OP:    "test",
			Path:  "/metadata/ownerReferences",
			Value: newCEP.OwnerReferences,
		},
		{
			OP:    "replace",
			Path:  "/status",
			Value: newCEP.Status,
		},
		{
			OP:    "replace",
			Path:  "/metadata/labels",
			Value: newCEP.Labels,
		},
	}
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		// unreachable
		return nil, err
	}

	return epSync.Clientset.CiliumV2().CiliumEndpoints(newCEP.Namespace).Patch(
		ctx,
		newCEP.Name,
		k8stypes.JSONPatchType,
		patchBytes,
		meta_v1.PatchOptions{},
	)
}

func (epSync *endpointSynchronizer) createCEP(ctx context.Context, newCEP *cilium_v2.CiliumEndpoint) (*cilium_v2.CiliumEndpoint, error) {
	return epSync.Clientset.CiliumV2().CiliumEndpoints(newCEP.Namespace).
		Create(ctx, newCEP, meta_v1.CreateOptions{})
}

// deleteCEP deletes the CEP for the given endpoint.
// It is careful not to delete CEPs that it does not own.
// It does this by matching on UID if possible, and if that fails
// or we didn't record the UID, it gets the CEP
// from the apiserver and checks that we are still the owner.
func (epSync *endpointSynchronizer) deleteCEP(ctx context.Context, log *slog.Logger, e *endpoint.Endpoint) error {
	ns := e.GetK8sNamespace()
	cepName := e.GetK8sCEPName()

	api := epSync.Clientset.CiliumV2().CiliumEndpoints(ns)

	// first attempt: delete with a UID precondition
	uid := e.GetCiliumEndpointUID()
	if uid != "" {
		err := api.Delete(
			ctx,
			cepName,
			*meta_v1.NewPreconditionDeleteOptions(string(uid)),
		)
		if err == nil || k8serrors.IsNotFound(err) {
			return nil
		}
		// Delete did not fail due to a precondition. Nothing more to do
		if !k8serrors.IsConflict(err) {
			return err
		}

		// We failed a precondition, which means the CEP's UID doesn't match our understanding.
		// Now we need to re-fetch and be careful
		log.Warn("CEP deletion failed due to precondition. Will re-fetch and retry", logfields.Error, err)
	}

	owner := e.GetCEPOwner()
	// now, either we have no UID or the precondition failed.
	// Fetch the CEP directly from the API, then check that we still own the CEP.
	existingCEP, err := api.Get(ctx, cepName, meta_v1.GetOptions{ResourceVersion: "0"})
	if k8serrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}

	// If this CEP has a different owner, we should not touch it.
	//
	// We are allowed, however, to touch CEPs without an owner. This can happen if someone
	// does `kubectl delete pod --cascade=orphan``, which removes OwnerReferences from
	// any downstream resources directly in the apisever.
	// Since we validate the node name below, this means it's still it's this agent's CEP
	wantOwnerRef := makeOwnerReferences(owner)
	if len(existingCEP.OwnerReferences) == 1 && existingCEP.OwnerReferences[0] != wantOwnerRef {
		log.Info("Skipping CEP deletion as it has a different owner")
		return nil
	}
	// skip deletion if CEP has a different node. It means
	// another agent has "taken over" this CEP
	if existingCEP.Status.NodeName != "" && existingCEP.Status.NodeName != epSync.nodeName {
		log.Info("Skipping CEP deletion as it has a different node")
		return nil
	}

	// Delete the CEP, with a ResourceVersion precondition to protect against the CEP being changed.
	err = api.Delete(ctx, cepName, *meta_v1.NewRVDeletionPrecondition(existingCEP.ResourceVersion))
	if err != nil && !k8serrors.IsNotFound(err) {
		return err
	}
	return nil
}
