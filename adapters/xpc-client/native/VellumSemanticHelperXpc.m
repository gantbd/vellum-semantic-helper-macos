#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

@protocol VellumSemanticHelperXpc
- (void)exchange:(NSData *)frame
                         snapshot:(NSFileHandle * _Nullable)snapshot
                            reply:(void (^)(NSData * _Nullable reply))reply;
@end

static const size_t VELLUM_MAX_XPC_FRAME_BYTES = 24 * 1024 * 1024;

int32_t vellum_semantic_helper_xpc_protocol_available(void) {
    return @protocol(VellumSemanticHelperXpc) == nil ? 0 : 1;
}

void * _Nullable vellum_semantic_helper_xpc_connect(
    const char *service_name,
    const char *code_signing_requirement,
    int32_t *error_out
) {
    @autoreleasepool {
        @try {
            NSString *service = [NSString stringWithUTF8String:service_name];
            NSString *requirement = [NSString stringWithUTF8String:code_signing_requirement];
            if (service == nil || requirement == nil) {
                *error_out = 1;
                return NULL;
            }
            NSXPCConnection *connection =
                [[NSXPCConnection alloc] initWithServiceName:service];
            connection.remoteObjectInterface =
                [NSXPCInterface interfaceWithProtocol:@protocol(VellumSemanticHelperXpc)];
            [connection setCodeSigningRequirement:requirement];
            [connection activate];
            *error_out = 0;
            return (__bridge_retained void *)connection;
        } @catch (__unused NSException *exception) {
            *error_out = 2;
            return NULL;
        }
    }
}

int32_t vellum_semantic_helper_xpc_exchange(
    void *connection_pointer,
    const uint8_t *request_bytes,
    size_t request_length,
    int32_t snapshot_fd,
    uint64_t timeout_millis,
    uint8_t **reply_bytes_out,
    size_t *reply_length_out
) {
    @autoreleasepool {
        if (connection_pointer == NULL || request_bytes == NULL ||
            request_length > VELLUM_MAX_XPC_FRAME_BYTES || timeout_millis == 0 ||
            reply_bytes_out == NULL || reply_length_out == NULL) {
            return 1;
        }
        *reply_bytes_out = NULL;
        *reply_length_out = 0;
        @try {
            NSXPCConnection *connection = (__bridge NSXPCConnection *)connection_pointer;
            dispatch_semaphore_t completed = dispatch_semaphore_create(0);
            __block BOOL transport_failed = NO;
            __block NSData *reply = nil;
            id<VellumSemanticHelperXpc> proxy =
                [connection remoteObjectProxyWithErrorHandler:
                    ^(__unused NSError *error) {
                        transport_failed = YES;
                        dispatch_semaphore_signal(completed);
                    }];
            NSData *request = [NSData dataWithBytes:request_bytes length:request_length];
            NSFileHandle *snapshot = snapshot_fd >= 0
                ? [[NSFileHandle alloc] initWithFileDescriptor:snapshot_fd closeOnDealloc:NO]
                : nil;
            [proxy exchange:request snapshot:snapshot reply:^(NSData *value) {
                reply = value;
                dispatch_semaphore_signal(completed);
            }];
            dispatch_time_t deadline = dispatch_time(
                DISPATCH_TIME_NOW,
                (int64_t)timeout_millis * NSEC_PER_MSEC
            );
            if (dispatch_semaphore_wait(completed, deadline) != 0) {
                [connection invalidate];
                return 5;
            }
            if (transport_failed || reply == nil ||
                reply.length > VELLUM_MAX_XPC_FRAME_BYTES) {
                return 2;
            }
            size_t length = reply.length;
            uint8_t *copy = length == 0 ? NULL : malloc(length);
            if (length != 0 && copy == NULL) {
                return 3;
            }
            if (length != 0) {
                memcpy(copy, reply.bytes, length);
            }
            *reply_bytes_out = copy;
            *reply_length_out = length;
            return 0;
        } @catch (__unused NSException *exception) {
            return 4;
        }
    }
}

void vellum_semantic_helper_xpc_free_bytes(uint8_t *bytes) {
    free(bytes);
}

void vellum_semantic_helper_xpc_invalidate(void *connection_pointer) {
    if (connection_pointer == NULL) {
        return;
    }
    @autoreleasepool {
        NSXPCConnection *connection = (__bridge_transfer NSXPCConnection *)connection_pointer;
        [connection invalidate];
    }
}
