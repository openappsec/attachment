package main

/*
#include <string.h>
#include "nano_attachment_common.h"
#include "nano_attachment.h"
#include <stdlib.h>
*/
import "C"
import (
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"

	"reflect"
	"unsafe"
	"os"
	"runtime"
)
func getEnv(key, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}
	return value
}

func copyToSlice(dest []byte, src unsafe.Pointer, size C.size_t, location int) int {
	C.memcpy(unsafe.Pointer(&dest[location]), src, size)
	return location + int(size)
}

func newNanoStr(data []byte) *C.nano_str_t {
	// Allocate memory for the nano_str_t struct
	nanoStr := (*C.nano_str_t)(C.malloc(C.size_t(unsafe.Sizeof(C.nano_str_t{}))))
	if nanoStr == nil {
		panic("failed to allocate memory for nano_str_t struct")
	}

	// Set the length of the data
	nanoStr.len = C.size_t(len(data))

	// Allocate memory for the data field and copy the Go byte slice into it
	// nanoStr.data = (*C.uchar)(C.malloc(C.size_t(len(data))))
	// if nanoStr.data == nil {
	// 	C.free(unsafe.Pointer(nanoStr))
	// 	panic("failed to allocate memory for data field")
	// }
	// copy((*[1 << 30]byte)(unsafe.Pointer(nanoStr.data))[:len(data):len(data)], data)

	return nanoStr
}

func createNanoStr(str string) C.nano_str_t {
    c_str := C.CString(str)
	// nanoStr := (*C.nano_str_t)(C.malloc(C.size_t(unsafe.Sizeof(C.nano_str_t{}))))
    nanoStr := C.nano_str_t{
        len:  C.size_t(len(str)),
        data: (*C.uchar)(unsafe.Pointer(c_str)),
    }

	// nanoStr.len = C.size_t(len(str))
	// nanoStr.data = (*C.uchar)(unsafe.Pointer(c_str))

    return nanoStr
}

func createNanoStrWithoutCopy(str string) C.nano_str_t {
    //c_str := C.CString(str)

    nanoStr := C.nano_str_t{
        len:  C.size_t(len(str)),
        data: (*C.uchar)(unsafe.Pointer((*(*reflect.StringHeader)(unsafe.Pointer(&str))).Data)),
    }

    return nanoStr
}

func freeNanoStr(str *C.nano_str_t) {
	C.free(unsafe.Pointer(str.data))
}

func freeHttpMetaDataFields(meta_data *C.HttpMetaData) {
	freeNanoStr(&(*meta_data).http_protocol)
	freeNanoStr(&(*meta_data).method_name)
	freeNanoStr(&(*meta_data).host)
	freeNanoStr(&(*meta_data).listening_ip)
	freeNanoStr(&(*meta_data).uri)
	freeNanoStr(&(*meta_data).client_ip)
}

func freeHeaders(header_arr *C.HttpHeaderData, header_slice []C.HttpHeaderData) {
	C.free(unsafe.Pointer(header_arr))

	for _, header := range header_slice {
		freeNanoStr(&(header.key))
		freeNanoStr(&(header.value))
	}
}

func RecoverPanic(ret *api.StatusType) {
	if e := recover(); e != nil {
		const size = 64 << 10
		buf := make([]byte, size)
		buf = buf[:runtime.Stack(buf, false)]
		api.LogErrorf("http: panic serving: %v\n%s", e, buf)

		*ret = api.Continue
	}
}