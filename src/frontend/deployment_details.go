package main

import (
	"context"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	//  Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	"k8s.io/client-go/tools/clientcmd"
)

var deploymentDetailsMap map[string]string
var log *logrus.Logger

func init() {
	initializeLogger()
	// Use a goroutine to ensure loadDeploymentDetails()'s GCP API
	// calls don't block non-GCP deployments. See issue #685.
	go loadDeploymentDetails()
}

func initializeLogger() {
	log = logrus.New()
	log.Level = logrus.DebugLevel
	log.Formatter = &logrus.JSONFormatter{
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "severity",
			logrus.FieldKeyMsg:   "message",
		},
		TimestampFormat: time.RFC3339Nano,
	}
	log.Out = os.Stdout
}

func loadDeploymentDetails() {
	deploymentDetailsMap = make(map[string]string)

	config, err := clientcmd.BuildConfigFromFlags("", "")
	if err != nil {
		log.Panicln("failed to create K8s config")
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Panicln("Failed to create K8s clientset")
	}

	nodeName := os.Getenv("KUBERNETES_NODE_NAME")
	if nodeName != "" {
		node, err := clientset.CoreV1().Nodes().Get(context.Background(), nodeName, v1.GetOptions{})
		if err != nil {
			log.Errorf("unable to get node %s %s", nodeName, err.Error())
		}
		zone := ""
		region := ""

		for k, a := range node.Labels {
			log.Infof("looking at label %s", k)

			if k == "topology.kubernetes.io/zone" {
				log.Infof("found zone label %s:%s", k, a)
				zone = a
			}
			if k == "topology.kubernetes.io/region" {
				log.Infof("found region label %s:%s", k, a)

				region = a
			}
		}

		deploymentDetailsMap["ZONE"] = zone
		deploymentDetailsMap["REGION"] = region
	}

	deploymentDetailsMap["HOSTNAME"] = os.Getenv("KUBERNETES_POD_NAME")
	deploymentDetailsMap["CLUSTERNAME"] = os.Getenv("KUBERNETES_CLUSTER_NAME")
	deploymentDetailsMap["CART_DISABLED"] = os.Getenv("CART_DISABLED")

	log.WithFields(logrus.Fields{
		"cluster":  deploymentDetailsMap["CLUSTERNAME"],
		"zone":     deploymentDetailsMap["ZONE"],
		"hostname": deploymentDetailsMap["HOSTNAME"],
	}).Debug("Loaded deployment details")
}
