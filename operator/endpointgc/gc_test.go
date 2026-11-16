// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointgc

import (
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	k8sTesting "k8s.io/client-go/testing"

	"github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/hive"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestEndpointGC(t *testing.T) {
	defer testutils.GoleakVerifyNone(
		t,
	)
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		cell.Provide(func() Config {
			return Config{
				CiliumEndpointGCInterval: 10 * time.Millisecond,
			}
		}),
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				DisableCiliumEndpointCRD: false,
			}
		}),
		metrics.Metric(NewMetrics),
		cell.Invoke(func(c *k8sClient.FakeClientset, cep resource.Resource[*cilium_v2.CiliumEndpoint]) {
			prepareCiliumEndpoints(t, c)
			ciliumEndpoint = cep
		}),
		cell.Invoke(func(p params) error {
			registerGC(p)
			return nil
		}),
	)

	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, t.Context()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}
	cepStore, _ := ciliumEndpoint.Store(t.Context())
	// wait for all CEPs to be deleted except for those with running pods or
	// cilium node owner reference
	waitForCEPs(t, cepStore, []string{
		"cep-valid-pod",
		"cep-stopped-pod-new",
		"cep-valid-no-nodename",
		"cep-stale-uid",
		"cep-non-pod",
	})
	if err := hive.Stop(tlog, t.Context()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestRegisterControllerCleanup(t *testing.T) {
	defer testutils.GoleakVerifyNone(
		t,
	)
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		cell.Provide(func() Config {
			return Config{
				CiliumEndpointGCInterval: 10 * time.Millisecond,
			}
		}),
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				DisableCiliumEndpointCRD: true,
			}
		}),
		metrics.Metric(NewMetrics),
		cell.Invoke(prepareCiliumEndpointCRD),
		cell.Invoke(func(c *k8sClient.FakeClientset, cep resource.Resource[*cilium_v2.CiliumEndpoint]) {
			prepareCiliumEndpoints(t, c)
			writeCEPCRD(t, c)
			ciliumEndpoint = cep
		}),
		cell.Invoke(func(p params) error {
			registerGC(p)
			return nil
		}),
	)

	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, t.Context()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}
	cepStore, _ := ciliumEndpoint.Store(t.Context())
	// wait for all CEPs to be deleted
	waitForCEPs(t, cepStore, nil)
	if err := hive.Stop(tlog, t.Context()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func TestRegisterControllerWithCRDDisabled(t *testing.T) {
	defer testutils.GoleakVerifyNone(
		t,
	)
	var ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint]
	var allCEPNames []string
	hive := hive.New(
		k8sClient.FakeClientCell(),
		k8s.ResourcesCell,
		metrics.Metric(NewMetrics),
		cell.Provide(func() Config {
			return Config{
				CiliumEndpointGCInterval: 100 * time.Millisecond,
			}
		}),
		cell.Provide(func() SharedConfig {
			return SharedConfig{
				DisableCiliumEndpointCRD: true,
			}
		}),
		cell.Invoke(func(c *k8sClient.FakeClientset, cep resource.Resource[*cilium_v2.CiliumEndpoint]) {
			allCEPNames = prepareCiliumEndpoints(t, c)
			ciliumEndpoint = cep
		}),
		cell.Invoke(func(p params) error {
			registerGC(p)
			return nil
		}),
	)
	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, t.Context()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}
	cepStore, _ := ciliumEndpoint.Store(t.Context())
	// wait for potential GC
	time.Sleep(500 * time.Millisecond)
	// gc is disabled so no CEPs should be deleted
	waitForCEPs(t, cepStore, allCEPNames)
	if err := hive.Stop(tlog, t.Context()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func prepareCiliumEndpointCRD(c *k8sClient.FakeClientset) error {
	c.APIExtFakeClientset.PrependReactor("get", "*", func(action k8sTesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, nil, nil
	})
	return nil
}

// writes a stub CEP CRD
func writeCEPCRD(t *testing.T, fakeClient *k8sClient.FakeClientset) {
	crd := &apiextensionsv1.CustomResourceDefinition{
		Name: cilium_api_v2.CEPName,
	}
	_, err := fakeClient.ApiextensionsV1().CustomResourceDefinitions().Create(
		t.Context(),
		crd,
		metav1.CreateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
}

func prepareCiliumEndpoints(t *testing.T, fakeClient *k8sClient.FakeClientset) []string {

	// Create Pods
	pod2 := createPod(t, fakeClient, "ns", "cep2", true)
	pod3 := createPod(t, fakeClient, "ns", "cep3", false)
	pod4 := createPod(t, fakeClient, "ns", "cep4", true)
	pod5 := createPod(t, fakeClient, "ns", "cep5", false)
	pod6 := createPod(t, fakeClient, "ns", "cep6", true)

	cepNames := []string{}
	createCEP := func(cep *cilium_v2.CiliumEndpoint) {
		_, err := fakeClient.CiliumV2().CiliumEndpoints(cep.Namespace).Create(t.Context(), cep, meta_v1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		cepNames = append(cepNames, cep.Name)
	}

	// Create set of Cilium Endpoints:
	// - CEP with no owner reference
	// - should be deleted
	cepNoOwner := makeCEP("cep-no-owner", "ns", nil)
	createCEP(cepNoOwner)

	// - CEP with owner reference pod that is running
	// - should not be deleted
	cepWithOwnerRunningPod := makeCEP("cep-valid-pod", "ns", pod2)
	createCEP(cepWithOwnerRunningPod)

	// - CEP with owner reference pod that is not running
	// - should be deleted
	cepWithOwnerNotRunningPod := makeCEP("cep-stopped-pod", "ns", pod3)
	createCEP(cepWithOwnerNotRunningPod)

	// - CEP with owner reference pod that is on a different node
	// - should be deleted
	cepWithWrongNode := makeCEP("cep-wrong-node", "ns", pod4)
	cepWithWrongNode.Status.NodeName = "wrong"
	createCEP(cepWithWrongNode)

	// - CEP with owner reference pod that is not running, but is new
	// - should be preserved even though the owning pod is not running
	cepWithRecentCreationTime := makeCEP("cep-stopped-pod-new", "ns", pod5)
	cepWithRecentCreationTime.CreationTimestamp = meta_v1.Now()
	createCEP(cepWithRecentCreationTime)

	// - CEP with empty node name
	// - should not be deleted
	cepWithNoNodeName := makeCEP("cep-valid-no-nodename", "ns", pod6)
	cepWithNoNodeName.Status.NodeName = ""
	createCEP(cepWithNoNodeName)

	// - CEP with different owner UID
	// - should not be deleeted
	cepWithStaleUID := makeCEP("cep-stale-uid", "ns", pod2)
	cepWithStaleUID.OwnerReferences[0].UID = "old"
	createCEP(cepWithStaleUID)

	cepNonPod := makeCEP("cep-non-pod", "ns", nil)
	cepNonPod.OwnerReferences = []metav1.OwnerReference{{
		Kind:       "CustomType",
		APIVersion: "example.com/SuperPod",
		Name:       "foo",
		UID:        "1234-5",
	}}
	createCEP(cepNonPod)
	return cepNames
}

func cepNames(cepStore resource.Store[*cilium_v2.CiliumEndpoint]) []string {
	l := cepStore.List()
	out := make([]string, 0, len(l))
	for _, cep := range l {
		out = append(out, cep.Name)
	}
	return out
}

func waitForCEPs(t *testing.T, cepStore resource.Store[*cilium_v2.CiliumEndpoint], remaining []string) {
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.ElementsMatch(c, cepNames(cepStore), remaining)
	}, 1*time.Second, 10*time.Millisecond, "failed to reach expected set of CEPs")
}

func makeCEP(name, namespace string, owner *slim_corev1.Pod) *cilium_v2.CiliumEndpoint {
	if name == "" {
		panic("bad name")
	}
	ep := &cilium_v2.CiliumEndpoint{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
	if owner != nil {
		ep.OwnerReferences = []meta_v1.OwnerReference{{
			APIVersion: "v1",
			Kind:       "Pod",
			Name:       owner.Name,
			UID:        owner.UID,
		}}
		ep.Status.NodeName = owner.Spec.NodeName
	}
	return ep
}

func createPod(t *testing.T, fc *k8sClient.FakeClientset, namespace, name string, isRunning bool) *slim_corev1.Pod {
	var phase slim_corev1.PodPhase
	if isRunning {
		phase = slim_corev1.PodRunning
	} else {
		phase = slim_corev1.PodSucceeded
	}
	pod := &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       k8stypes.UID(name),
		},
		Status: slim_corev1.PodStatus{
			Phase: phase,
		},
		Spec: slim_corev1.PodSpec{
			NodeName: "foo",
		},
	}
	var err error
	pod, err = fc.Slim().CoreV1().Pods(namespace).Create(t.Context(), pod, meta_v1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return pod
}
