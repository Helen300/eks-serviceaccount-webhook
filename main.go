package main

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	admission "k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	tlsDir             = `/etc/mutator/certs`
	tlsCertFile        = `cert.pem`
	tlsKeyFile         = `key.pem`
	VirtioFSContainers = "virtiofs-containers"
	VirtShareDir       = "/var/run/kubevirt"
)

var (
	podResource = metav1.GroupVersionResource{Version: "v1", Resource: "pods"}
)

// applySecurityDefaults implements the logic of our example admission controller webhook. For every pod that is created
// (outside of Kubernetes namespaces), it first checks if `runAsNonRoot` is set. If it is not, it is set to a default
// value of `false`. Furthermore, if `runAsUser` is not set (and `runAsNonRoot` was not initially set), it defaults
// `runAsUser` to a value of 1234.
//
// To demonstrate how requests can be rejected, this webhook further validates that the `runAsNonRoot` setting does
// not conflict with the `runAsUser` setting - i.e., if the former is set to `true`, the latter must not be `0`.
// Note that we combine both the setting of defaults and the check for potential conflicts in one webhook; ideally,
// the latter would be performed in a validating webhook admission controller.
func mountServiceAccountsTokens(req *admission.AdmissionRequest) ([]patchOperation, error) {
	// This handler should only get called on Pod objects as per the MutatingWebhookConfiguration in the YAML file.
	// However, if (for whatever reason) this gets invoked on an object of a different kind, issue a log message but
	// let the object request pass through otherwise.
	if req.Resource != podResource {
		log.Printf("expect resource to be %s", podResource)
		return nil, nil
	}

	// Parse the Pod object.
	raw := req.Object.Raw
	pod := corev1.Pod{}
	if _, _, err := universalDeserializer.Decode(raw, nil, &pod); err != nil {
		return nil, fmt.Errorf("could not deserialize pod object: %v", err)
	}

	if value, ok := pod.Labels["kubevirt.io"]; !ok && value != "virt-launcher" {
		return nil, nil
	}

	// Extract containers
	containers := pod.Spec.Containers
	if len(containers) == 0 {
		return nil, nil
	}

	// All the virtiofs containers have the same spec
	var virtiofsContainer corev1.Container
	for _, container := range containers {
		if strings.Contains(container.Name, "virtiofs") {
			// Get the virtiofs container for the kube service account token
			for _, arg := range container.Args {
				if strings.Contains(arg, "/var/run/secrets/kubernetes.io") {
					virtiofsContainer = container
					break
				}
			}
		}
	}

	// Check for additional service account secret mounts
	additionalServiceAccountTokenMounts := findAdditionalServiceAccountMounts(containers)
	if len(additionalServiceAccountTokenMounts) == 0 {
		return nil, nil
	}

	// Create patch operations to apply sensible defaults, if those options are not set explicitly.
	// Create virtiofs containers for each additional mount
	addiitonalVirtioFSContainers := generateVirtioFSContainers(virtiofsContainer, additionalServiceAccountTokenMounts)

	// Patch the spec to add virtiofs containers and volumes
	patches := createPatches(addiitonalVirtioFSContainers, pod.Spec.Containers, "/spec/containers")
	if len(patches) == 0 {
		return nil, nil
	}

	return patches, nil
}

func getAudience(mountPath string) string {
	log.Infof("Mount path: %v", mountPath)
	parts := strings.Split(mountPath, "/")
	log.Infof("Mount path parts: %v", parts)
	// Since the pattern has a known structure, the wildcard will be the 5th element.
	// The index is 4 because it's 0-based.
	log.Infof("Mount path parts: %v", parts)
	splitAudience := strings.Split(parts[4], ".")
	return splitAudience[0]
}

func getSocketName(audience string) string {
	return "serviceaccount-" + audience
}

// TODO: Make specific to EKS, right now this searches for all tokens mounted at a particular path
func findAdditionalServiceAccountMounts(containers []corev1.Container) map[string]string {
	additionalMounts := map[string]string{}

	for _, containerObj := range containers {

		volumeMounts := containerObj.VolumeMounts
		if len(volumeMounts) == 0 {
			continue
		}

		for _, mountObj := range volumeMounts {
			mountPath := mountObj.MountPath
			if len(mountPath) == 0 {
				continue
			}

			// Check if mount path matches additional service account paths
			if matched, _ := filepath.Match("/var/run/secrets/*/serviceaccount", mountPath); matched && mountPath != "/var/run/secrets/kubernetes.io/serviceaccount" {
				audience := getAudience(mountPath)
				additionalMounts[getSocketName(audience)] = mountPath
			}
		}
	}
	log.Infof("Additional mounts are %s", additionalMounts)
	return additionalMounts
}

func generateVirtioFSContainers(existingContainer corev1.Container, additionalServiceAccountTokenMounts map[string]string) []corev1.Container {

	containers := []corev1.Container{}
	for name, tokenPath := range additionalServiceAccountTokenMounts {
		container := generate(existingContainer, name, tokenPath)
		containers = append(containers, container)
	}

	return containers
}

var VirtioFSContainersMountBaseDir = filepath.Join(VirtShareDir, VirtioFSContainers)

func virtioFSSocketPath(name string) string {
	socketName := fmt.Sprintf("%s.sock", name)
	return filepath.Join(VirtioFSContainersMountBaseDir, socketName)
}

func generate(container corev1.Container, name string, mountPoint string) corev1.Container {

	socketPathArg := fmt.Sprintf("--socket-path=%s", virtioFSSocketPath(name))
	sourceArg := fmt.Sprintf("--shared-dir=%s", mountPoint)
	// Always sandbox none for service account volumes
	args := []string{socketPathArg, sourceArg, "--cache=auto", "--sandbox=none"}

	volumeMounts := []corev1.VolumeMount{
		// This is required to pass socket to compute
		{
			Name:      VirtioFSContainers,
			MountPath: VirtioFSContainersMountBaseDir,
		},
	}

	return corev1.Container{
		Name:            fmt.Sprintf("virtiofs-%s", name),
		Image:           container.Image,
		ImagePullPolicy: container.ImagePullPolicy,
		Command:         []string{"/usr/libexec/virtiofsd"},
		Args:            args,
		VolumeMounts:    volumeMounts,
		Resources:       container.Resources,
		SecurityContext: container.SecurityContext,
	}
}

func createPatches[T any](newCollection []T, existingCollection []T, path string) []patchOperation {
	var patches []patchOperation
	for index, item := range newCollection {
		indexPath := path
		var value interface{}
		first := index == 0 && len(existingCollection) == 0
		if !first {
			indexPath = indexPath + "/-"
			value = item
		} else {
			value = []T{item}
		}
		patches = append(patches, patchOperation{
			Op:    "add",
			Path:  indexPath,
			Value: value,
		})
	}
	return patches
}

func main() {
	certPath := filepath.Join(tlsDir, tlsCertFile)
	keyPath := filepath.Join(tlsDir, tlsKeyFile)

	mux := http.NewServeMux()
	mux.Handle("/mutate", admitFuncHandler(mountServiceAccountsTokens))
	server := &http.Server{
		// We listen on port 8443 such that we do not need root privileges or extra capabilities for this server.
		// The Service object will take care of mapping this port to the HTTPS port 443.
		Addr:    ":8443",
		Handler: mux,
	}
	log.Fatal(server.ListenAndServeTLS(certPath, keyPath))
}

