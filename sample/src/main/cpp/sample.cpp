#include <jni.h>
#include <string>
#include <android/log.h>

#include "adl.h"

extern "C" JNIEXPORT jstring JNICALL
Java_com_owttwo_andlinker_sample_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "ADL C++";
    void *handle = adlopen("/system/bin/linker64", 0);
    void *symbol = adlsym(handle, "__loader_dlopen");
    __android_log_print(ANDROID_LOG_INFO, "sample", "__loader_dlopen symbol = %p", symbol);
    return env->NewStringUTF(hello.c_str());
}
