// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !requirefips

package azure

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/monitor/query/azmetrics"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

type queryResourceClientConfig struct {
	endpoint   string
	credential azcore.TokenCredential
	options    *azmetrics.ClientOptions
}

// MonitorService service wrapper to the azure sdk for go
type MonitorService struct {
	metricsClient             *armmonitor.MetricsClient
	metricDefinitionClient    *armmonitor.MetricDefinitionsClient
	metricNamespaceClient     *armmonitor.MetricNamespacesClient
	resourceClient            *armresources.Client
	queryResourceClientConfig queryResourceClientConfig
	context                   context.Context
	log                       *logp.Logger
}

const (
	metricNameLimit        = 20
	ApiVersion             = "2021-04-01"
	BatchApiResourcesLimit = 50
)

// NewService instantiates the Azure monitoring service
func NewService(config Config, logger *logp.Logger) (*MonitorService, error) {
	cloudServicesConfig := cloud.AzurePublic.Services

	resourceManagerConfig := cloudServicesConfig[cloud.ResourceManager]

	if config.ResourceManagerEndpoint != "" && config.ResourceManagerEndpoint != DefaultBaseURI {
		resourceManagerConfig.Endpoint = config.ResourceManagerEndpoint
	}

	if config.ResourceManagerAudience != "" {
		resourceManagerConfig.Audience = config.ResourceManagerAudience
	}

	clientOptions := policy.ClientOptions{
		Cloud: cloud.Configuration{
			Services:                     cloudServicesConfig,
			ActiveDirectoryAuthorityHost: config.ActiveDirectoryEndpoint,
		},
	}

	credential, err := azidentity.NewClientSecretCredential(config.TenantId, config.ClientId, config.ClientSecret,
		&azidentity.ClientSecretCredentialOptions{
			ClientOptions: clientOptions,
		})
	if err != nil {
		return nil, fmt.Errorf("couldn't create client credentials: %w", err)
	}

	metricsClient, err := armmonitor.NewMetricsClient(credential, &arm.ClientOptions{
		ClientOptions: clientOptions,
	})
	if err != nil {
		return nil, fmt.Errorf("couldn't create metrics client: %w", err)
	}

	metricsDefinitionClient, err := armmonitor.NewMetricDefinitionsClient(credential, &arm.ClientOptions{
		ClientOptions: clientOptions,
	})
	if err != nil {
		return nil, fmt.Errorf("couldn't create metric definitions client: %w", err)
	}

	resourceClient, err := armresources.NewClient(config.SubscriptionId, credential, &arm.ClientOptions{
		ClientOptions: clientOptions,
	})
	if err != nil {
		return nil, fmt.Errorf("couldn't create resources client: %w", err)
	}

	metricNamespaceClient, err := armmonitor.NewMetricNamespacesClient(credential, &arm.ClientOptions{
		ClientOptions: clientOptions,
	})
	if err != nil {
		return nil, fmt.Errorf("couldn't create metric namespaces client: %w", err)
	}

	queryResourceClientConfig := queryResourceClientConfig{
		credential: credential,
		options: &azmetrics.ClientOptions{
			ClientOptions: clientOptions,
		},
	}

	service := &MonitorService{
		metricDefinitionClient:    metricsDefinitionClient,
		metricsClient:             metricsClient,
		metricNamespaceClient:     metricNamespaceClient,
		resourceClient:            resourceClient,
		queryResourceClientConfig: queryResourceClientConfig,
		context:                   context.Background(),
		log:                       logger.Named("azure monitor service"),
	}

	return service, nil
}

// GetResourceDefinitions will retrieve the azure resources based on the options entered
func (service MonitorService) GetResourceDefinitions(id []string, group []string, rType string, query string) ([]*armresources.GenericResourceExpanded, error) {
	var resourceQuery string
	var resourceList []*armresources.GenericResourceExpanded

	if len(id) > 0 {
		// listing multiple resourceId conditions does not seem to work with the API, extracting the name and resource type does not work as the position of the `resourceType` can move if a parent resource is involved, filtering by resource name and resource group (if extracted) is also not possible as
		// different types of resources can contain the same name.
		for _, id := range id {
			filter := fmt.Sprintf("resourceId eq '%s'", id)
			pager := service.resourceClient.NewListPager(&armresources.ClientListOptions{
				Filter: &filter,
			})

			for pager.More() {
				nextResult, err := pager.NextPage(service.context)
				if err != nil {
					return nil, err
				}

				if len(nextResult.Value) > 0 {
					resourceList = append(resourceList, nextResult.Value...)
				}
			}
		}

		return resourceList, nil
	}

	switch {
	case len(group) > 0:
		var filterList []string

		for _, gr := range group {
			filterList = append(filterList, fmt.Sprintf("resourceGroup eq '%s'", gr))
		}

		resourceQuery = strings.Join(filterList, " OR ")
		if rType != "" {
			resourceQuery = fmt.Sprintf("(%s) AND resourceType eq '%s'", resourceQuery, rType)
		}
	case query != "":
		resourceQuery = query
	}

	var tempResourceList []*armresources.GenericResourceExpanded

	pager := service.resourceClient.NewListPager(&armresources.ClientListOptions{
		Filter: &resourceQuery,
	})
	for pager.More() {
		nextResult, err := pager.NextPage(service.context)
		if err != nil {
			return nil, err
		}

		tempResourceList = append(tempResourceList, nextResult.Value...)
	}

	resourceList = tempResourceList

	return resourceList, nil
}

// GetResourceDefinitionById will retrieve the azure resource based on the resource Id
func (service MonitorService) GetResourceDefinitionById(id string) (armresources.GenericResource, error) {
	resp, err := service.resourceClient.GetByID(service.context, id, ApiVersion, nil)
	if err != nil {
		return armresources.GenericResource{}, err
	}

	return resp.GenericResource, nil
}

// GetMetricNamespaces will return all supported namespaces based on the resource id and namespace
func (service *MonitorService) GetMetricNamespaces(resourceId string) (armmonitor.MetricNamespaceCollection, error) {
	pager := service.metricNamespaceClient.NewListPager(resourceId, nil)

	metricNamespaceCollection := armmonitor.MetricNamespaceCollection{}

	for pager.More() {
		nextPage, err := pager.NextPage(service.context)
		if err != nil {
			return armmonitor.MetricNamespaceCollection{}, err
		}

		metricNamespaceCollection.Value = append(metricNamespaceCollection.Value, nextPage.Value...)
	}

	return metricNamespaceCollection, nil
}

// sleepIfPossible will check for the error 429 in the azure response, and look for the retry after header.
// If the header is present, then metricbeat will sleep for that duration, otherwise it will return an error.
func (service *MonitorService) sleepIfPossible(err error, resourceId string, namespace string) error {
	errorMsg := "no metric definitions were found for resource " + resourceId + " and namespace " + namespace

	var respError *azcore.ResponseError
	ok := errors.As(err, &respError)
	if !ok {
		return fmt.Errorf("%s, failed to cast error to azcore.ResponseError", errorMsg)
	}
	// Check for TooManyRequests error and retry if it is the case
	if respError.StatusCode != http.StatusTooManyRequests {
		return fmt.Errorf("%s, %w", errorMsg, err)
	}

	// Check if the error has the header Retry After.
	// If it is present, then we should try to make this request again.
	retryAfter := respError.RawResponse.Header.Get("Retry-After")
	if retryAfter == "" {
		return fmt.Errorf("%s %w, failed to find Retry-After header", errorMsg, err)
	}

	duration, errD := time.ParseDuration(retryAfter + "s")
	if errD != nil {
		return fmt.Errorf("%s, failed to parse duration %s from header retry after", errorMsg, retryAfter)
	}

	service.log.Infof("%s, metricbeat will try again after %s seconds", errorMsg, retryAfter)
	time.Sleep(duration)
	service.log.Infof("%s, metricbeat finished sleeping and will try again now", errorMsg)

	return nil
}

// GetMetricDefinitionsWithRetry will return all supported metrics based on the resource id and namespace
// It will check for an error when moving the pager to the next page, and retry if possible.
func (service *MonitorService) GetMetricDefinitionsWithRetry(resourceId string, namespace string) (armmonitor.MetricDefinitionCollection, error) {
	opts := &armmonitor.MetricDefinitionsClientListOptions{}

	if namespace != "" {
		opts.Metricnamespace = &namespace
	}

	pager := service.metricDefinitionClient.NewListPager(resourceId, opts)

	metricDefinitionCollection := armmonitor.MetricDefinitionCollection{}

	for pager.More() {
		nextPage, err := pager.NextPage(service.context)
		if err != nil {
			retryError := service.sleepIfPossible(err, resourceId, namespace)
			if retryError != nil {
				return armmonitor.MetricDefinitionCollection{}, err
			}
			continue
		}
		metricDefinitionCollection.Value = append(metricDefinitionCollection.Value, nextPage.Value...)
	}

	return metricDefinitionCollection, nil
}

func (service *MonitorService) QueryResources(
	resourceIDs []string,
	subscriptionID string,
	namespace string,
	timegrain string,
	startTime string,
	endTime string,
	metricNames []string,
	aggregations string,
	filter string,
	location string) ([]azmetrics.MetricData, error) {

	var tg *string
	var top int32
	//var interval string

	if timegrain != "" {
		tg = &timegrain
	}

	// API fails with bad request if filter value is sent empty.
	var metricsFilter *string

	if filter != "" {
		metricsFilter = &filter
		// set top as a high value, otherwise default is only 10
		top = int32(1000)
	}

	opts := azmetrics.QueryResourcesOptions{
		Aggregation: &aggregations,
		Filter:      metricsFilter,
		Interval:    tg,
		StartTime:   &startTime,
		EndTime:     &endTime,
		Top:         &top,
	}

	resp := []azmetrics.MetricData{}

	service.queryResourceClientConfig.endpoint = fmt.Sprintf("https://%s.metrics.monitor.azure.com", location)
	queryResourceClient, err := azmetrics.NewClient(
		service.queryResourceClientConfig.endpoint,
		service.queryResourceClientConfig.credential,
		service.queryResourceClientConfig.options,
	)
	if err != nil {
		return nil, err
	}
	service.log.Infof("QueryResources to be called. length of resources is %d", len(resourceIDs))
	// call the query resources client passing 50 resourceIDs at a time
	for i := 0; i < len(resourceIDs); i += BatchApiResourcesLimit {
		end := i + BatchApiResourcesLimit

		if end > len(resourceIDs) {
			end = len(resourceIDs)
		}
		r, err := queryResourceClient.QueryResources(
			service.context,
			subscriptionID,
			namespace,
			metricNames,
			azmetrics.ResourceIDList{
				ResourceIDs: resourceIDs[i:end],
			},
			&opts,
		)

		if err != nil {
			return nil, err
		}

		resp = append(resp, r.MetricResults.Values...)
	}

	return resp, nil

}

// GetMetricValues will return the metric values based on the resource and metric details
func (service *MonitorService) GetMetricValues(resourceId string, namespace string, timegrain string, timespan string, metricNames []string, aggregations string, filter string) ([]armmonitor.Metric, string, error) {
	var tg *string
	var interval string

	if timegrain != "" {
		tg = &timegrain
	}

	// orderBy := ""
	resultTypeData := armmonitor.ResultTypeData

	// check for limit of requested metrics (20)
	var metrics []armmonitor.Metric

	// API fails with bad request if filter value is sent empty.
	var metricsFilter *string

	if filter != "" {
		metricsFilter = &filter
	}

	for i := 0; i < len(metricNames); i += metricNameLimit {
		end := i + metricNameLimit

		if end > len(metricNames) {
			end = len(metricNames)
		}

		metricNames := strings.Join(metricNames[i:end], ",")

		opts := &armmonitor.MetricsClientListOptions{
			Aggregation: &aggregations,
			Filter:      metricsFilter,
			Interval:    tg,
			Metricnames: &metricNames,
			Timespan:    &timespan,
			Top:         nil,
			// Orderby:         &orderBy,
			ResultType: &resultTypeData,
		}

		if namespace != "" {
			opts.Metricnamespace = &namespace
		}

		resp, err := service.metricsClient.List(service.context, resourceId, opts)

		// check for applied charges before returning any errors
		if resp.Cost != nil && *resp.Cost != 0 {
			service.log.Warnf("Charges amounted to %v are being applied while retrieving the metric values from the resource %s ", *resp.Cost, resourceId)
		}

		if err != nil {
			return metrics, "", err
		}

		interval = *resp.Interval

		for _, v := range resp.Value {
			metrics = append(metrics, *v)
		}
	}

	return metrics, interval, nil
}

// getResourceNameFormId maps resource group from resource ID
func getResourceNameFromId(path string) string {
	params := strings.Split(path, "/")
	if strings.HasSuffix(path, "/") {
		return params[len(params)-2]
	}
	return params[len(params)-1]

}

// getResourceTypeFromId maps resource group from resource ID
func getResourceTypeFromId(path string) string {
	params := strings.Split(path, "/")
	for i, param := range params {
		if param == "providers" {
			return fmt.Sprintf("%s/%s", params[i+1], params[i+2])
		}
	}
	return ""
}
