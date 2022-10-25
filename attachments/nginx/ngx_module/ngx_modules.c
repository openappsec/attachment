// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// @file ngx_modules.c
/// \brief This file is generated from configuration and hold the data structures connecting the plugin to the server

#include <ngx_config.h>
#include <ngx_core.h>

extern ngx_module_t  ngx_http_cp_attachment_module;

ngx_module_t *ngx_modules[] = {
    &ngx_http_cp_attachment_module,
    NULL
};

char *ngx_module_names[] = {
    "ngx_http_cp_attachment_module",
    NULL
};

char *ngx_module_order[] = {
    "ngx_http_cp_attachment_module",
    "ngx_http_copy_filter_module",
    NULL
};
