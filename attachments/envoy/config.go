package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"

	xds "github.com/cncf/xds/go/xds/type/v3"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	envoyHttp "github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/http"
)

/*
#include <pthread.h>

unsigned long get_thread_id() {
    return (unsigned long)pthread_self();
}

#include "nano_attachment_common.h"
#include "nano_initializer.h"
#include "nano_attachment.h"
*/
import "C"

const Name = "cp_nano_filter"

const Admin_api = "http://127.0.0.1:%s/server_info"

var filter_id atomic.Int64

type nano_attachment C.struct_NanoAttachment

var attachments_map map[int]*nano_attachment = nil
var thread_to_attachment_mapping map[int]int = nil
var attachment_to_thread_mapping map[int]int = nil

var attachment_to_filter_request_structs map[int]*filterRequestStructs = nil

var mutex sync.Mutex

const keep_alive_interval = 10 * time.Second

var last_keep_alive time.Time

// EnvoyServerInfo represents the structure of the JSON response from /server_info
type EnvoyServerInfo struct {
	Concurrency int `json:"concurrency"`
}

// getEnvoyConcurrency fetches and returns the concurrency level of Envoy from the admin API
func getEnvoyConcurrency(admin_api_address string) (int, error) {
	resp, err := http.Get(admin_api_address)
	if err != nil {
		return 0, fmt.Errorf("failed to reach Envoy admin API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status code from Envoy admin API: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read response body: %w", err)
	}

	var info EnvoyServerInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return 0, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	return info.Concurrency, nil
}

func configurationServer() {
    r := chi.NewRouter()

    r.Get("/load-config", func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		defer mutex.Unlock()
		worker_ids := make([]int, 0)
		workersParam := r.URL.Query().Get("workers")
		num_of_workers := len(attachments_map) // concurrency
		if workersParam == "" {
			for i := 0; i < num_of_workers; i++ {
				worker_ids = append(worker_ids, i)
			}
		} else {
			workers := strings.Split(workersParam, ",")
			for _, worker := range workers {
				worker_id, err := strconv.Atoi(worker)

				if worker_id >= num_of_workers {
					api.LogWarnf(
						"Can not load configuration of invalid worker ID %d. worker ID should be lower than: %d",
						worker_id,
						num_of_workers)
				}

				if err != nil || worker_id >= num_of_workers {
					w.WriteHeader(http.StatusBadRequest)
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(fmt.Sprintf(`{"error": "invalid worker ID: %s"}`, worker)))
					return
				}
				worker_ids = append(worker_ids, worker_id)
			}
		}

		workers_reload_status := make(map[string]string, len(worker_ids))
		res := C.NANO_OK
		for _, worker_id := range worker_ids {
			worker_reload_res := C.RestartAttachmentConfiguration((*C.NanoAttachment)(attachments_map[worker_id]))
			if worker_reload_res == C.NANO_ERROR {
				res = C.NANO_ERROR
				workers_reload_status[strconv.Itoa(worker_id)] = "Reload Configuraiton Failed"
				continue
			}
			workers_reload_status[strconv.Itoa(worker_id)] = "Reload Configuraiton Succeded"
		}

		response, err :=  json.Marshal(workers_reload_status)
		if err != nil {
			api.LogWarnf("Error while sending reponse about reload configuration. Err: %s", err.Error())
			response = []byte(`{"error": "Internal Error"}`)
		}

		if res == C.NANO_ERROR || err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}

        w.Header().Set("Content-Type", "application/json")
        w.Write(response)
    })

    http.ListenAndServe(":8119", r)
}

func init() {
	last_keep_alive = time.Time{}
	envoyHttp.RegisterHttpFilterFactoryAndConfigParser(Name, ConfigFactory, &parser{})
	//envoyHttp.RegisterHttpFilterConfigFactoryAndParser(Name, ConfigFactory, &parser{})
	go configurationServer()
}

type config struct {}

type parser struct {}

func sendKeepAlive() {
	for {
		attachment_ptr := (*C.NanoAttachment)(attachments_map[0])
		if attachment_ptr == nil {
			return
		}

		C.SendKeepAlive(attachment_ptr)
		time.Sleep(30 * time.Second)
	}
}

func (p *parser) initFilterStructs() *filterRequestStructs {
	return &filterRequestStructs {
		http_start_data:     (*C.HttpRequestFilterData)(C.malloc(C.sizeof_HttpRequestFilterData)),
		http_meta_data:      (*C.HttpMetaData)(C.malloc(C.sizeof_HttpMetaData)),
		http_headers:        (*C.HttpHeaders)(C.malloc(C.sizeof_HttpHeaders)),
		http_headers_data:   (*C.HttpHeaderData)(C.malloc(10000 * C.sizeof_HttpHeaderData)),
		http_res_headers:    (*C.ResHttpHeaders)(C.malloc(C.sizeof_ResHttpHeaders)),
		http_body_data:      (*C.nano_str_t)(C.malloc(10000 * C.sizeof_nano_str_t)),
		attachment_data:     (*C.AttachmentData)(C.malloc(C.sizeof_AttachmentData)),
	}
}

// Parse the filter configuration. We can call the ConfigCallbackHandler to control the filter's
// behavior
func (p *parser) Parse(any *anypb.Any, callbacks api.ConfigCallbackHandler) (interface{}, error) {
	conf := &config{}

	if attachments_map != nil {
		api.LogInfof("Waf Configuration already loaded")
		return conf, nil
	}

	var num_of_workers int
	concurrency_method := getEnv("CONCURRENCY_CALC", "numOfCores")

	if concurrency_method == "numOfCores" {
		num_of_workers = runtime.NumCPU()
		api.LogInfof("using number of cpu cores %d", num_of_workers)
	} else if concurrency_method == "config" {
		config_port := getEnv("CONFIG_PORT", "15000")
		admin_api := fmt.Sprintf(Admin_api, config_port)
		workers, err := getEnvoyConcurrency(admin_api)
		if err != nil {
			api.LogWarnf("unable to fetch concurrency from admin server, using cpu cores. err: %s", err.Error())
			num_of_workers = runtime.NumCPU()
		} else {
			num_of_workers = workers
		}
	} else if concurrency_method == "custom" {
		conc_number := getEnv("CONCURRENCY_NUMBER", "-1")
		if conc_number == "-1" {
			api.LogWarnf("concurrency number is not set as an env variable, using cpu cores")
			num_of_workers = runtime.NumCPU()
		} else if conc_num, err := strconv.Atoi(conc_number); err == nil && conc_num > 0 {
			num_of_workers = conc_num
		} else {
			api.LogWarnf("error converting conc_number %s, using num of cpu cores", conc_number)
			num_of_workers = runtime.NumCPU()
		}
	} else {
		api.LogWarnf("unable to fetch concurrency from %s, using cpu cores", concurrency_method)
		num_of_workers = runtime.NumCPU()
	}

	configStruct := &xds.TypedStruct{}
	if err := any.UnmarshalTo(configStruct); err != nil {
		return nil, err
	}

	attachments_map = make(map[int]*nano_attachment)
	attachment_to_filter_request_structs = make(map[int]*filterRequestStructs)
	attachment_to_thread_mapping = make(map[int]int, 0)
	thread_to_attachment_mapping = make(map[int]int, 0)
	api.LogInfof("Number of worker threds: %d", num_of_workers)
	for worker_id := 0; worker_id < num_of_workers; worker_id++ {

		attachment := C.InitNanoAttachment(C.uint8_t(0), C.int(worker_id), C.int(num_of_workers), C.int(C.fileno(C.stdout)))
		for attachment == nil {
			api.LogWarnf("attachment is nill going to sleep for two seconds and retry")
			time.Sleep(2 * time.Second)
			attachment = C.InitNanoAttachment(C.uint8_t(0), C.int(worker_id), C.int(num_of_workers), C.int(C.fileno(C.stdout)))
		}

		//mutex.Lock()
		attachments_map[worker_id] = (*nano_attachment)(attachment)
		attachment_to_filter_request_structs[worker_id] = p.initFilterStructs()
		//mutex.Unlock()
	}

	go func (){
		sendKeepAlive()
	}()

	return conf, nil
}

// Merge configuration from the inherited parent configuration
func (p *parser) Merge(parent interface{}, child interface{}) interface{} {
	parentConfig := parent.(*config)

	// copy one, do not update parentConfig directly.
	newConfig := *parentConfig
	return &newConfig
}

// func ConfigFactory(c interface{}) api.StreamFilterFactory {
// 	conf, ok := c.(*config)
// 	if !ok {
// 		panic("unexpected config type")
// 	}

// 	return func(callbacks api.FilterCallbackHandler) api.StreamFilter {
// 		worker_thread_id := int(C.get_thread_id())
// 		api.LogDebugf("worker_thread_id: %d", worker_thread_id)
// 		if _, ok := thread_to_attachment_mapping[int(worker_thread_id)]; !ok {
// 			api.LogDebugf("need to add new thread to the map")
// 			map_size := len(attachment_to_thread_mapping)
// 			if map_size < len(attachments_map) {
// 				attachment_to_thread_mapping[map_size] = worker_thread_id
// 				thread_to_attachment_mapping[worker_thread_id] = map_size
// 				api.LogDebugf("len(attachment_to_thread_mapping): %d", len(attachment_to_thread_mapping))
// 				api.LogDebugf("thread_to_attachment_mapping: %v", thread_to_attachment_mapping)
// 				api.LogDebugf("attachment_to_thread_mapping: %v", attachment_to_thread_mapping)
// 			} else {
// 				panic("unexpected thread id")
// 			}
// 		}

// 		worker_id := thread_to_attachment_mapping[int(worker_thread_id)]
// 		api.LogDebugf("worker_id: %d", worker_id)

// 		filter_id.Add(1)
// 		session_id := filter_id.Load()
// 		attachment_ptr := attachments_map[worker_id]
// 		session_data := C.InitSessionData((*C.NanoAttachment)(attachment_ptr), C.SessionID(session_id))

// 		return &filter{
// 			callbacks: callbacks,
// 			config:    conf,
// 			session_id: session_id,
// 			cp_attachment: attachment_ptr,
// 			session_data: session_data,
// 			request_structs: attachment_to_filter_request_structs[worker_id],
// 		}
// 	}
// }

func ConfigFactory(c interface{}, callbacks api.FilterCallbackHandler) api.StreamFilter {
	conf, ok := c.(*config)
	if !ok {
		panic("unexpected config type")
	}

	worker_thread_id := int(C.get_thread_id())
	api.LogDebugf("worker_thread_id: %d", worker_thread_id)
	if _, ok := thread_to_attachment_mapping[int(worker_thread_id)]; !ok {
		api.LogDebugf("need to add new thread to the map")
		map_size := len(attachment_to_thread_mapping)
		if map_size < len(attachments_map) {
			attachment_to_thread_mapping[map_size] = worker_thread_id
			thread_to_attachment_mapping[worker_thread_id] = map_size
			api.LogDebugf("len(attachment_to_thread_mapping): %d", len(attachment_to_thread_mapping))
			api.LogDebugf("thread_to_attachment_mapping: %v", thread_to_attachment_mapping)
			api.LogDebugf("attachment_to_thread_mapping: %v", attachment_to_thread_mapping)
		} else {
			panic("unexpected thread id")
		}
	}

	worker_id := thread_to_attachment_mapping[int(worker_thread_id)]
	api.LogDebugf("worker_id: %d", worker_id)

	filter_id.Add(1)
	session_id := filter_id.Load()
	attachment_ptr := attachments_map[worker_id]
	session_data := C.InitSessionData((*C.NanoAttachment)(attachment_ptr), C.SessionID(session_id))

	return &filter{
		callbacks: callbacks,
		config:    conf,
		session_id: session_id,
		cp_attachment: attachment_ptr,
		session_data: session_data,
		request_structs: attachment_to_filter_request_structs[worker_id],
	}
}


func main() {}
