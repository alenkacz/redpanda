package patch

import (
	"fmt"

	"emperror.dev/errors"
	"github.com/banzaicloud/k8s-objectmatcher/patch"
	json "github.com/json-iterator/go"
)

// IgnoreVolumeMode
func IgnoreVolumeMode() patch.CalculateOption {
	return func(current, modified []byte) ([]byte, []byte, error) {
		current, err := deleteDefaultVolumeMode(current)
		if err != nil {
			return []byte{}, []byte{}, errors.Wrap(err, "could not delete status field from current byte sequence")
		}
		modified, err = deleteDefaultVolumeMode(modified)
		if err != nil {
			return []byte{}, []byte{}, errors.Wrap(err, "could not delete status field from modified byte sequence")
		}
		return current, modified, nil
	}
}

func deleteDefaultVolumeMode(obj []byte) ([]byte, error) {
	resource := map[string]interface{}{}
	err := json.Unmarshal(obj, &resource)
	if err != nil {
		return []byte{}, fmt.Errorf("could not unmarshal byte sequence. %w", err)
	}

	if spec, ok := resource["spec"]; ok {
		if spec, ok := spec.(map[string]interface{}); ok {
			if vcts, ok := spec["volumeClaimTemplates"]; ok {
				if vcts, ok := vcts.([]interface{}); ok {
					for _, vct := range vcts {
						if vct, ok := vct.(map[string]interface{}); ok {
							if vctSpec, ok := vct["spec"]; ok {
								if vctSpec, ok := vctSpec.(map[string]interface{}); ok {
									if vctSpec["volumemode"] == corev1.PersistentVolumeFilesystem {
										vctSpec["volumemode"] = ""
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
