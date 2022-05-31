package main

import "strings"

func getShortName(kind string) string {
	switch strings.ToLower(kind) {
	case "service":
		return "svc"
	case "serviceaccount":
		return "sa"
	case "rolebinding":
		return "rb"
	case "clusterrolebinding":
		return "crb"
	case "clusterrole":
		return "cr"
	case "horizontalpodautoscaler":
		return "hpa"
	case "poddisruptionbudget":
		return "pdb"
	case "customresourcedefinition":
		return "crd"
	case "configmap":
		return "cm"
	}

	return strings.ToLower(kind)

}
