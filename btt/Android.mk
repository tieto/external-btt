LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=  btt_daemon_adapter.c \
                    btt_daemon_misc.c \
                    btt_daemon_main.c \
                    btt_main.c \
                    btt_adapter.c \
                    btt_rfcomm.c   \
                    btt_tester.c \
                    btt_utils.c

LOCAL_MODULE := btt
LOCAL_MODULE_TAGS := optional

LOCAL_SHARED_LIBRARIES := \
    libhardware \
    libcutils

LOCAL_SYSTEM_SHARED_LIBRARIES := libc libdl

LOCAL_CFLAGS += -Wall -Wextra -Wno-unused -Werror -O0 -g -DDEVELOPMENT_VERSION=1
LOCAL_STRIP_MODULE := false

include $(BUILD_EXECUTABLE)
