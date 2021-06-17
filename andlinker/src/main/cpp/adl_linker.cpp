//
// Created by P7XXTM1-G on 5/20/2021.
//

#include "adl_linker.h"
#include "adl_util.h"
#include "adl_loader.h"

__BEGIN_DECLS

/**
 * >= android 5.0, dl_iterate_phdr is supported
 * @return
 */
extern __attribute((weak)) int
dl_iterate_phdr(int (*)(struct dl_phdr_info *, size_t, void *), void *);

int adl_do_iterate_phdr(adl_iterate_phdr_cb callback, void *data) {
    int level = adl_get_api_level();
    int result;
    if (level < __ANDROID_API_L__) {
        return adl_iterate_library_by_maps(callback, data);
    } else if (level < __ANDROID_API_O_MR1__) {
        static dl_phdr_info *info = NULL;
        if (info == NULL) {
            info = adl_read_linker_by_maps();
        }
        if (info != NULL) {
            result = callback(info, sizeof(dl_phdr_info), data);
            if (result != 0) {
                return result;
            }
        }
    }

    adl_loader_lock();
    result = dl_iterate_phdr(callback, data);
    adl_loader_unlock();
    return result;
}

__END_DECLS
