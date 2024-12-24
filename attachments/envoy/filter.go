package main

/*
#include <pthread.h>

unsigned long get_thread_id_2() {
    return (unsigned long)pthread_self();
}

#include <stdlib.h>
#include <string.h>
#include "nano_attachment_common.h"
#include "nano_attachment.h"

HttpHeaderData* createHttpHeaderDataArray(int size) {
    return (HttpHeaderData*)malloc(size * sizeof(HttpHeaderData));
}

HttpMetaData* createHttpMetaData() {
    return (HttpMetaData*)malloc(sizeof(HttpMetaData));
}

void setHeaderElement(HttpHeaderData* arr, int index, nano_str_t key, nano_str_t value) {
	if (arr == NULL) {
		return;
	}

    arr[index].key = key;
    arr[index].value = value;
}
*/
import "C"
import (
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"

	"strconv"
	"strings"
	"unsafe"
)

func convertBlockPageToString(block_page C.BlockPageData) string {
	block_page_size := block_page.title_prefix.len +
		block_page.title.len +
		block_page.body_prefix.len +
		block_page.body.len +
		block_page.uuid_prefix.len +
		block_page.uuid.len +
		block_page.uuid_suffix.len

	block_page_bytes := make([]byte, block_page_size)

	location := 0
	location = copyToSlice(
		block_page_bytes,
		unsafe.Pointer(block_page.title_prefix.data),
		C.size_t(block_page.title_prefix.len),
		location)

	location = copyToSlice(
		block_page_bytes,
		unsafe.Pointer(block_page.title.data),
		C.size_t(block_page.title.len),
		location)

	location = copyToSlice(
		block_page_bytes,
		unsafe.Pointer(block_page.body_prefix.data),
		C.size_t(block_page.body_prefix.len),
		location)

	location = copyToSlice(
		block_page_bytes,
		unsafe.Pointer(block_page.body.data),
		C.size_t(block_page.body.len),
		location)

	location = copyToSlice(
		block_page_bytes,
		unsafe.Pointer(block_page.uuid_prefix.data),
		C.size_t(block_page.uuid_prefix.len),
		location)

	location = copyToSlice(
		block_page_bytes,
		unsafe.Pointer(block_page.uuid.data),
		C.size_t(block_page.uuid.len),
		location)

	copyToSlice(
		block_page_bytes,
		unsafe.Pointer(block_page.uuid_suffix.data),
		C.size_t(block_page.uuid_suffix.len),
		location)

	return string(block_page_bytes)
}

// The callbacks in the filter, like `DecodeHeaders`, can be implemented on demand.
// Because api.PassThroughStreamFilter provides a default implementation.
type filter struct {
	api.PassThroughStreamFilter

	callbacks     api.FilterCallbackHandler
	path          string
	config        *config
	session_id    int64
	session_data  *C.HttpSessionData
	cp_attachment *nano_attachment
	request_structs *filterRequestStructs
}

type filterRequestStructs struct {
	http_start_data           *C.HttpRequestFilterData
	http_meta_data            *C.HttpMetaData
	http_headers              *C.HttpHeaders
	http_headers_data         *C.HttpHeaderData
	http_res_headers          *C.ResHttpHeaders
	http_body_data            *C.nano_str_t
	attachment_data           *C.AttachmentData
}

func (f *filterRequestStructs) ZeroInitialize() {
	if f.http_start_data != nil {
		C.memset(unsafe.Pointer(f.http_start_data), 0, C.size_t(unsafe.Sizeof(*f.http_start_data)))
	}
	if f.http_meta_data != nil {
		C.memset(unsafe.Pointer(f.http_meta_data), 0, C.size_t(unsafe.Sizeof(*f.http_meta_data)))
	}
	if f.http_headers != nil {
		C.memset(unsafe.Pointer(f.http_headers), 0, C.size_t(unsafe.Sizeof(*f.http_headers)))
	}
	if f.http_headers_data != nil {
		C.memset(unsafe.Pointer(f.http_headers_data), 0, C.size_t(unsafe.Sizeof(*f.http_headers_data)))
	}
	if f.attachment_data != nil {
		C.memset(unsafe.Pointer(f.attachment_data), 0, C.size_t(unsafe.Sizeof(*f.attachment_data)))
	}
}

func (f *filter) isSessionFinalized() bool {
	return C.IsSessionFinalized((*C.NanoAttachment)(f.cp_attachment), (*C.HttpSessionData)(f.session_data)) == 1
}

func (f *filter) sendData(data unsafe.Pointer, chunkType C.HttpChunkType) C.AttachmentVerdictResponse {

	attachment_data := f.request_structs.attachment_data
	attachment_data.session_id = C.uint32_t(f.session_id)
	attachment_data.chunk_type = chunkType       // Adjust type as needed
	attachment_data.session_data = f.session_data           // Ensure `f.session_data` is compatible
	attachment_data.data = C.DataBuffer(data)               // Ensure `data` is compatible with `C.DataBuffer`

	return C.SendDataNanoAttachment((*C.NanoAttachment)(f.cp_attachment), attachment_data)
}

func (f *filter) handleCustomResponse(verdict_response *C.AttachmentVerdictResponse) api.StatusType {
	if verdict_response.web_response_data.web_response_type == C.CUSTOM_WEB_RESPONSE {
		headers := map[string][]string{
			"Content-Type": []string{"text/html"},
		}
		block_page_parts := C.GetBlockPage(
			(*C.NanoAttachment)(f.cp_attachment),
			(*C.HttpSessionData)(f.session_data),
			(*C.AttachmentVerdictResponse)(verdict_response))
		return f.sendLocalReplyInternal(int(block_page_parts.response_code), convertBlockPageToString(block_page_parts), headers)
	}

	redirect_data := C.GetRedirectPage(
		(*C.NanoAttachment)(f.cp_attachment),
		(*C.HttpSessionData)(f.session_data),
		(*C.AttachmentVerdictResponse)(verdict_response))
	redirect_location := redirect_data.redirect_location

	redirect_location_slice := unsafe.Slice((*byte)(unsafe.Pointer(redirect_location.data)), redirect_location.len)
	headers := map[string][]string{
		"Location": []string{string(redirect_location_slice)},
	}

	return f.sendLocalReplyInternal(307, "", headers)
}

func (f *filter) finalizeRequest(verdict_response *C.AttachmentVerdictResponse) api.StatusType {
	if C.AttachmentVerdict(verdict_response.verdict) == C.ATTACHMENT_VERDICT_DROP {
		return f.handleCustomResponse(verdict_response)
	}

	return api.Continue
}

func (f *filter) handleHeaders(header api.HeaderMap) {
	const envoy_headers_prefix = "x-envoy"
	i := 0
	header.Range(func(key, value string) bool {
		if i > 10000 {
			return true
		}

		api.LogInfof("inserting headers: key %s, value %s", key, value)

		if 	strings.HasPrefix(key, envoy_headers_prefix) ||
			key == "x-request-id" ||
			key == ":method" ||
			key == ":path" ||
			key == ":scheme" ||
			key == "x-forwarded-proto" {
			return true
		}

		if key == ":authority" {
			key = "Host"
		}

		key_nano_str := createNanoStrWithoutCopy(key)
		value_nano_str := createNanoStrWithoutCopy(value)
		C.setHeaderElement((*C.HttpHeaderData)(f.request_structs.http_headers_data), C.int(i), key_nano_str, value_nano_str)
		i++
		return true
	})

	http_headers := f.request_structs.http_headers
	http_headers.data = f.request_structs.http_headers_data
	http_headers.headers_count = C.size_t(i)
}

func (f *filter) sendBody(buffer api.BufferInstance, is_req bool) C.AttachmentVerdictResponse {
	chunk_type := C.HTTP_REQUEST_BODY
	if !is_req {
		chunk_type = C.HTTP_RESPONSE_BODY
	}

	data := buffer.Bytes()
	data_len := len(data)
	buffer_size := 8 * 1024

	// body_chunk := newNanoStr(data)
	// body_chunk.data = (*C.uchar)(unsafe.Pointer(&data[0]))

	num_of_buffers := ((data_len - 1) / buffer_size) + 1

	// TO DO: FIX THIS ASAP
	if num_of_buffers > 10000 {
		num_of_buffers = 10000
	}


	for i := 0; i < num_of_buffers; i++ {
		nanoStrPtr := (*C.nano_str_t)(unsafe.Pointer(uintptr(unsafe.Pointer(f.request_structs.http_body_data)) + uintptr(i)*unsafe.Sizeof(*f.request_structs.http_body_data)))
		nanoStrPtr.data = (*C.uchar)(unsafe.Pointer(&data[i * buffer_size]))

		if i + 1 == num_of_buffers {
			nanoStrPtr.len = C.size_t(data_len - (i * buffer_size))
		} else {
			nanoStrPtr.len = C.size_t(buffer_size)
		}

	}

	http_chunks_array := C.HttpBody{
		data:         f.request_structs.http_body_data,
		bodies_count: C.size_t(num_of_buffers),
	}

	api.LogInfof("sending body data: %+v", http_chunks_array)
	return f.sendData(unsafe.Pointer(&http_chunks_array), C.HttpChunkType(chunk_type))

}

func (f *filter) sendStartTransaction(start_transaction_data *C.HttpRequestFilterData) C.AttachmentVerdictResponse {
	return f.sendData(unsafe.Pointer(&start_transaction_data), C.HTTP_REQUEST_FILTER)
}

func (f *filter) handleStartTransaction(header api.RequestHeaderMap) {
	stream_info := f.callbacks.StreamInfo()

	ip_location := 0
	port_location := 1

	listening_address := stream_info.DownstreamLocalAddress()
	listening_address_arr := strings.Split(listening_address, ":")
	listening_port, _ := strconv.Atoi(listening_address_arr[port_location])

	client_address := stream_info.DownstreamRemoteAddress()
	client_addr_arr := strings.Split(client_address, ":")
	client_port, _ := strconv.Atoi(client_addr_arr[port_location])

	host := strings.Split(header.Host(), ":")[0]

	protocol, _ := stream_info.Protocol()

	// init start transaction struct
	meta_data := f.request_structs.http_meta_data
	meta_data.http_protocol = createNanoStr(protocol)
	meta_data.method_name = createNanoStr(header.Method())
	meta_data.host = createNanoStr(host)
	meta_data.listening_ip = createNanoStr(listening_address_arr[ip_location])
	meta_data.listening_port = C.uint16_t(listening_port)
	meta_data.uri = createNanoStr(header.Path())
	meta_data.client_ip = createNanoStr(client_addr_arr[ip_location])
	meta_data.client_port = C.uint16_t(client_port)
}

func (f *filter) sendLocalReplyInternal(ret_code int, custom_response string, headers map[string][]string) api.StatusType {
	//f.callbacks.DecoderFilterCallbacks().SendLocalReply(ret_code, custom_response, headers, 0, "") // new api
	// var headers_map map[string]string = nil
	// if headers != nil {
	// 	headers_map = make(map[string]string)
	// 	for key, val := range headers {
	// 		header_val := ""
	// 		if len(val) > 0 {
	// 			header_val = val[0]
	// 		}

	// 		headers_map[key] = header_val
	// 	}
	// }
	f.callbacks.DecoderFilterCallbacks().SendLocalReply(ret_code, custom_response, headers, 0, "")
	return api.LocalReply
}

func (f *filter) endInspectionPart(chunk_type C.HttpChunkType) api.StatusType {
	api.LogInfof("Ending inspection for current chunk")
	res := f.sendData(nil, chunk_type)

	if C.AttachmentVerdict(res.verdict) != C.ATTACHMENT_VERDICT_INSPECT {
		api.LogInfof("got final verict: %v", res.verdict)
		return f.finalizeRequest(&res)
	}

	return api.Continue
}

// Callbacks which are called in request path
// The endStream is true if the request doesn't have body
func (f *filter) DecodeHeaders(header api.RequestHeaderMap, endStream bool) api.StatusType {
	ret := api.Continue

	defer RecoverPanic(&ret)

	if f.isSessionFinalized() {
		api.LogInfof("session has already been inspected, no need for further inspection")
		return api.Continue
	}

	f.handleStartTransaction(header)
	f.handleHeaders(header)

	http_start_data := f.request_structs.http_start_data
	http_start_data.meta_data =  f.request_structs.http_meta_data
	http_start_data.req_headers = f.request_structs.http_headers
	http_start_data.contains_body = C.bool(!endStream)

	res := f.sendData(unsafe.Pointer(http_start_data), C.HTTP_REQUEST_FILTER)
	if C.AttachmentVerdict(res.verdict) != C.ATTACHMENT_VERDICT_INSPECT {
		api.LogInfof("got final verict: %v", res.verdict)
		return f.finalizeRequest(&res)
	}

	return ret
}

// DecodeData might be called multiple times during handling the request body.
// The endStream is true when handling the last piece of the body.
func (f *filter) DecodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	ret := api.Continue

	defer RecoverPanic(&ret)

	if f.isSessionFinalized() {
		return api.Continue
	}

	if endStream && buffer.Len() == 0 {
		return f.endInspectionPart(C.HttpChunkType(C.HTTP_REQUEST_END))
	}

	if buffer.Len() == 0 {
		return ret
	}

	res := f.sendBody(buffer, true)
	if C.AttachmentVerdict(res.verdict) != C.ATTACHMENT_VERDICT_INSPECT {
		api.LogInfof("got final verict: %v", res.verdict)
		return f.finalizeRequest(&res)
	}

	if endStream {
		return f.endInspectionPart(C.HttpChunkType(C.HTTP_REQUEST_END))
	}

	return ret
}

// Callbacks which are called in response path
// The endStream is true if the response doesn't have body
func (f *filter) EncodeHeaders(header api.ResponseHeaderMap, endStream bool) api.StatusType {
	ret := api.Continue

	defer RecoverPanic(&ret)

	if f.isSessionFinalized() {
		return api.Continue
	}

	const content_length_key = "content-length"
	const status_code_key = ":status"


	content_length_str, _ := header.Get(content_length_key)
	status_code_str, _ := header.Get(status_code_key)
	content_length, _ := strconv.Atoi(content_length_str)
	status_code, _ := strconv.Atoi(status_code_str)

	f.handleHeaders(header)
	res_http_headers := f.request_structs.http_res_headers
	res_http_headers.headers = f.request_structs.http_headers
	res_http_headers.content_length = C.uint64_t(content_length)
	res_http_headers.response_code = C.uint16_t(status_code)

	res := f.sendData(unsafe.Pointer(res_http_headers), C.HTTP_RESPONSE_HEADER)
	if C.AttachmentVerdict(res.verdict) != C.ATTACHMENT_VERDICT_INSPECT {
		api.LogInfof("got final verict: %v", res.verdict)
		return f.finalizeRequest(&res)
	}

	if endStream {
		return f.endInspectionPart(C.HttpChunkType(C.HTTP_RESPONSE_END))
	}

	return ret
}

// EncodeData might be called multiple times during handling the response body.
// The endStream is true when handling the last piece of the body.
func (f *filter) EncodeData(buffer api.BufferInstance, endStream bool) api.StatusType {
	ret := api.Continue

	defer RecoverPanic(&ret)

	if f.isSessionFinalized() {
		return api.Continue
	}

	if endStream && buffer.Len() == 0 {
		return f.endInspectionPart(C.HttpChunkType(C.HTTP_RESPONSE_END))
	}

	if buffer.Len() == 0 {
		return ret
	}

	res := f.sendBody(buffer, false)
	if C.AttachmentVerdict(res.verdict) != C.ATTACHMENT_VERDICT_INSPECT {
		api.LogInfof("got final verict: %v", res.verdict)
		return f.finalizeRequest(&res)
	}

	if endStream {
		return f.endInspectionPart(C.HttpChunkType(C.HTTP_RESPONSE_END))
	}

	return ret
}

// ____________NOT IMPLEMENTED AT THE MOMENT____________
func (f *filter) DecodeTrailers(trailers api.RequestTrailerMap) api.StatusType {
	// support suspending & resuming the filter in a background goroutine
	return api.Continue
}

func (f *filter) EncodeTrailers(trailers api.ResponseTrailerMap) api.StatusType {
	return api.Continue
}

// OnLog is called when the HTTP stream is ended on HTTP Connection Manager filter.
func (f *filter) OnLog(api.RequestHeaderMap, api.RequestTrailerMap, api.ResponseHeaderMap, api.ResponseTrailerMap) {}

// OnLogDownstreamStart is called when HTTP Connection Manager filter receives a new HTTP request
// (required the corresponding access log type is enabled)
func (f *filter) OnLogDownstreamStart(api.RequestHeaderMap) {}

// OnLogDownstreamPeriodic is called on any HTTP Connection Manager periodic log record
// (required the corresponding access log type is enabled)
func (f *filter) OnLogDownstreamPeriodic(api.RequestHeaderMap, api.RequestTrailerMap, api.ResponseHeaderMap, api.ResponseTrailerMap) {}

func (f *filter) OnDestroy(reason api.DestroyReason) {
	freeHttpMetaDataFields(f.request_structs.http_meta_data)
	f.request_structs.ZeroInitialize()
	C.FiniSessionData((*C.NanoAttachment)(f.cp_attachment), f.session_data)
}
