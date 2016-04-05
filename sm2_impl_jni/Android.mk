# sm2 jni lib for android
#
# Author : Simon Pang of catt2009 / steven.psm@gmail.com 
# 2012-11-8
#
# Andoid make file

LOCAL_PATH:= $(call my-dir)


include $(CLEAR_VARS)

src_files:= \
  sm2_jni.cpp   utils.cpp 
       
LOCAL_MODULE    := sm2U

LOCAL_SRC_FILES := $(src_files)

LOCAL_C_INCLUDES := $(LOCAL_PATH)\
                  $(LOCAL_PATH)/../appVerifyLib/include

LOCAL_STATIC_LIBRARIES := sm2impl tommath 
#crypto_a
#LOCAL_CPP_FEATURES := exceptions
LOCAL_SHARED_LIBRARIES := crypto  
#hardware_legacy
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog  -ldl  -lz
              
include $(BUILD_SHARED_LIBRARY)


