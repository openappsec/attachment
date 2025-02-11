#ifndef __NANO_COMPRESSION_H__
#define __NANO_COMPRESSION_H__

#include "nano_attachment_sender_thread.h"

/// @brief Compresses the given HTTP body using the specified compression type in the session data.
///
/// @param attachment Pointer to the NanoAttachment structure.
/// @param bodies Pointer to the HttpBody structure containing the data to be compressed.
/// @param session_data_p Pointer to the HttpSessionData structure containing session-specific data.
///
/// @return Pointer to a new HttpBody structure containing the compressed data,
/// or NULL if compression is not needed or fails.
HttpBody *nano_compress_body(
    NanoAttachment *attachment,
    HttpBody *bodies,
    HttpSessionData *session_data_p
);

/// @brief Decompresses the given HTTP body using the specified compression type in the session data.
///
/// @param attachment Pointer to the NanoAttachment structure.
/// @param bodies Pointer to the HttpBody structure containing the data to be decompressed.
/// @param session_data_p Pointer to the HttpSessionData structure containing session-specific data.
///
/// @return Pointer to a new HttpBody structure containing the decompressed data,
/// or NULL if decompression is not needed or fails.
HttpBody *nano_decompress_body(
    NanoAttachment *attachment,
    HttpBody *bodies,
    HttpSessionData *session_data_p
);

/// @brief Frees the memory allocated for the compressed HTTP body.
///
/// @param attachment Pointer to the NanoAttachment structure.
/// @param bodies Pointer to the HttpBody structure containing the compressed data to be freed.
/// @param session_data_p Pointer to the HttpSessionData structure containing session-specific data.
void nano_free_compressed_body(
    NanoAttachment *attachment,
    HttpBody *bodies,
    HttpSessionData *session_data_p
);

#endif // __NANO_COMPRESSION_H__
