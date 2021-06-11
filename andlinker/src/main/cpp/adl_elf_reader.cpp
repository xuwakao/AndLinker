//
// Created by P7XXTM1-G on 6/9/2021.
//
#include <sys/mman.h>
#include <cstdlib>
#include <fcntl.h>

#include "adl_elf_reader.h"
#include "adl_util.h"

__BEGIN_DECLS

bool map_file_fragment::map(int fd, size_t file_sz, off64_t base_offset,
                            size_t elf_offset, size_t size) {
    off64_t offset;
    adl_safe_add(&offset, base_offset, elf_offset);

    off64_t page_min = adl_page_start(offset);
    off64_t end_offset;

    adl_safe_add(&end_offset, offset, size);
    adl_safe_add(&end_offset, end_offset, adl_page_offset(offset));

    size_t map_size = static_cast<size_t>(end_offset - page_min);
    uint8_t *map_start = static_cast<uint8_t *>(
            mmap64(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, page_min));
    if (map_start == MAP_FAILED) {
        return false;
    }

    map_start_ = map_start;
    map_size_ = map_size;

    data_ = map_start + adl_page_offset(offset);
    size_ = size;
    return true;
}

void map_file_fragment::unmap(void) const {
    if (map_start_ != NULL) {
        munmap(map_start_, map_size_);
    }
}

bool elf_reader::read_elf_header(bool force) {
    if (header_ != NULL && !force)
        return true;

    if (!openFile())
        return false;

    ssize_t rc = pread64(fd_, &header_, sizeof(header_), file_offset_);
    if (rc < 0) {
        ADLOGE("can't read file \"%s\"", name_);
        return false;
    }

    if (rc != sizeof(header_)) {
        ADLOGE("\"%s\" is too small to be an ELF executable: only found %zd bytes", name_,
               static_cast<size_t>(rc));
        return false;
    }
    return true;
}

bool elf_reader::verify_elf_header(void) {
    if (header_ == NULL) {
        return false;
    }
    if (memcmp(header_->e_ident, ELFMAG, SELFMAG) != 0) {
        ADLOGE("\"%s\" has bad ELF magic: %02x%02x%02x%02x", name_,
               header_->e_ident[0], header_->e_ident[1], header_->e_ident[2], header_->e_ident[3]);
        return false;
    }

    if (header_->e_ident[EI_DATA] != ELFDATA2LSB) {
        ADLOGE("\"%s\" not little-endian: %d", name_, header_->e_ident[EI_DATA]);
        return false;
    }

    if (header_->e_type != ET_DYN) {
        ADLOGE("\"%s\" has unexpected e_type: %d", name_, header_->e_type);
        return false;
    }

    if (header_->e_version != EV_CURRENT) {
        ADLOGE("\"%s\" has unexpected e_version: %d", name_, header_->e_version);
        return false;
    }

    if (header_->e_shentsize != sizeof(ElfW(Shdr))) {
        // Fail if app is targeting Android O or above
        if (adl_get_api_level() >= 26) {
            ADLOGE("\"%s\" has unsupported e_shentsize: 0x%x (expected 0x%zx)",
                   name_, header_->e_shentsize, sizeof(ElfW(Shdr)));
            return false;
        }
        ADLOGW("invalid-elf-header_section-headers-enforced-for-api-level-26, "
               "\"%s\" has unsupported e_shentsize 0x%x (expected 0x%zx)",
               name_, header_->e_shentsize, sizeof(ElfW(Shdr)));
        ADLOGW(name_, "has invalid ELF header");
    }

    if (header_->e_shstrndx == 0) {
        // Fail if app is targeting Android O or above
        if (adl_get_api_level() >= 26) {
            ADLOGE("\"%s\" has invalid e_shstrndx", name_);
            return false;
        }

        ADLOGW("invalid-elf-header_section-headers-enforced-for-api-level-26, "
               "\"%s\" has invalid e_shstrndx", name_);
        ADLOGW(name_, "has invalid ELF header");
    }
    return true;
}

// Loads the program header table from an ELF file into a read-only private
// anonymous mmap-ed block.
bool elf_reader::read_program_headers(void) {
    phdr_num_ = header_->e_phnum;
    if (phdr_table_ != NULL)
        return true;

    if (!openFile()) return false;

    if (phdr_fragment_ == NULL) {
        phdr_fragment_ = static_cast<map_file_fragment *>(
                calloc(1, sizeof(map_file_fragment)));
    }

    // Like the kernel, we only accept program header tables that
    // are smaller than 64KiB.
    if (phdr_num_ < 1 || phdr_num_ > 65536 / sizeof(ElfW(Phdr))) {
        ADLOGE("\"%s\" has invalid e_phnum: %zd", name_, phdr_num_);
        return false;
    }

    // Boundary checks
    size_t size = phdr_num_ * sizeof(ElfW(Phdr));
    if (!check_file_range(header_->e_phoff, size, alignof(ElfW(Phdr)))) {
        ADLOGE("\"%s\" has invalid phdr offset/size: %zu/%zu",
               name_,
               static_cast<size_t>(header_->e_phoff),
               size);
        return false;
    }

    if (!phdr_fragment_->map(fd_, file_size_, file_offset_, header_->e_phoff, size)) {
        ADLOGE("\"%s\" phdr mmap failed", name_);
        return false;
    }

    phdr_table_ = static_cast<ElfW(Phdr) *>(phdr_fragment_->data_);
    return true;
}

bool elf_reader::read_section_headers(void) {
    if (!openFile()) return false;

    shdr_num_ = header_->e_shnum;
    if (shdr_num_ == 0) {
        ADLOGW("\"%s\" has no section headers", name_);
        return false;
    }

    if (shdr_fragment_ == NULL) {
        shdr_fragment_ = static_cast<map_file_fragment *>(
                calloc(1, sizeof(map_file_fragment)));
    }

    size_t size = shdr_num_ * sizeof(ElfW(Shdr));
    if (!check_file_range(header_->e_shoff, size, alignof(const ElfW(Shdr)))) {
        ADLOGW("\"%s\" has invalid shdr offset/size: %zu/%zu",
               name_,
               static_cast<size_t>(header_->e_shoff),
               size);
        return false;
    }

    if (!shdr_fragment_->map(fd_, file_size_, file_offset_, header_->e_shoff, size)) {
        ADLOGE("\"%s\" shdr mmap failed", name_);
        return false;
    }

    shdr_table_ = static_cast<const ElfW(Shdr) *>(shdr_fragment_->data_);
    return true;
}

/**
 * .shstrtab --> .symtab --> .strtab
 * @return
 */
bool elf_reader::read_other_section(void) {
    if (!openFile()) return false;

    if (header_->e_shstrndx == SHN_UNDEF) return false;

    const ElfW(Shdr) *shstrtab_shdr = &shdr_table_[header_->e_shstrndx];

    if (!check_file_range(shstrtab_shdr->sh_offset, shstrtab_shdr->sh_size,
                          alignof(const char))) {
        ADLOGE("\"%s\" has invalid offset/size of the .shstrtab section",
               name_);
        return false;
    }

    if (shstrtab_fragment_ == NULL) {
        shstrtab_fragment_ = static_cast<map_file_fragment *>(
                calloc(1, sizeof(map_file_fragment)));
    }

    if (!shstrtab_fragment_->map(fd_, file_size_, file_offset_, shstrtab_shdr->sh_offset,
                                 shstrtab_shdr->sh_size)) {
        ADLOGE("\"%s\" .shstrtab section mmap failed", name_);
        return false;
    }

    shstrtab_ = static_cast<const char *>(shstrtab_fragment_->data_);
    shstrtab_size_ = shstrtab_fragment_->size_;

    for (const ElfW(Shdr) *shdr = shdr_table_;
         shdr < shdr_table_ + header_->e_shnum; shdr++) {
        const char *shdr_name = shstrtab_ + shdr->sh_name;

        //find the .symtab
        if (SHT_SYMTAB != shdr->sh_type || strcmp(".symtab", shdr_name) != 0)
            continue;

        //.symtab link to .strtab
        if (shdr->sh_link >= header_->e_shnum) {
            ADLOGW("\"%s\" .symtab section sh_link invalid", name_);
            continue;
        }

        const ElfW(Shdr *)shdr_strtab = &shdr_table_[shdr->sh_link];
        if (shdr_strtab->sh_type != SHT_STRTAB) {
            continue;
        }
        if (!check_file_range(shdr->sh_offset, shdr->sh_size,
                              alignof(const char))) {
            ADLOGE("\"%s\" has invalid offset/size of the .symtab section",
                   name_);
            return false;
        }

        if (symtab_fragment_ == NULL) {
            symtab_fragment_ = static_cast<map_file_fragment *>(
                    calloc(1, sizeof(map_file_fragment)));
        }

        if (!symtab_fragment_->map(fd_, file_size_, file_offset_, shdr->sh_offset,
                                   shdr->sh_size)) {
            ADLOGE("\"%s\" symtab section mmap failed", name_);
            return false;
        }
        symtab_ = reinterpret_cast<ElfW(Sym) *>(symtab_fragment_->data_);
        symtab_num_ = shdr->sh_size / shdr->sh_entsize;

        if (!check_file_range(shdr_strtab->sh_offset, shdr_strtab->sh_size,
                              alignof(const char))) {
            ADLOGE("\"%s\" has invalid offset/size of the .strtab section",
                   name_);
            return false;
        }

        if (strtab_fragment_ == NULL) {
            strtab_fragment_ = static_cast<map_file_fragment *>(
                    calloc(1, sizeof(map_file_fragment)));
        }

        if (!strtab_fragment_->map(fd_, file_size_, file_offset_, shdr_strtab->sh_offset,
                                   shdr_strtab->sh_size)) {
            ADLOGE("\"%s\" .strtab section mmap failed", name_);
            return false;
        }

        strtab_ = static_cast<const char *>(strtab_fragment_->data_);
        strtab_size_ = shdr_strtab->sh_size;
        break;
    }
    return true;
}

bool elf_reader::check_file_range(ElfW(Addr) offset,
                                  size_t size, size_t alignment) const {
    off64_t range_start;
    off64_t range_end;

    // Only header can be located at the 0 offset... This function called to
    // check DYNSYM and DYNAMIC sections and phdr/shdr - none of them can be
    // at offset 0.

    return offset > 0 &&
           adl_safe_add(&range_start, file_offset_, offset) &&
           adl_safe_add(&range_end, range_start, size) &&
           (range_start < file_size_) &&
           (range_end <= file_size_) &&
           ((offset % alignment) == 0);
}

void elf_reader::recycle(void) {
    if (phdr_fragment_ != NULL) {
        phdr_fragment_->unmap();
        phdr_table_ = NULL;
    }

    if (shdr_fragment_ != NULL) {
        shdr_fragment_->unmap();
        shdr_table_ = NULL;
    }

    if (shstrtab_fragment_ != NULL) {
        shstrtab_fragment_->unmap();
        shstrtab_ = NULL;
    }

    if (symtab_fragment_ != NULL) {
        symtab_fragment_->unmap();
        symtab_ = NULL;
    }

    if (strtab_fragment_ != NULL) {
        strtab_fragment_->unmap();
        strtab_ = NULL;
    }

    if (fd_ != 1) {
        close(fd_);
        fd_ = -1;
    }
    free((void *) real_path_);
    real_path_ = NULL;
}

bool elf_reader::openFile(void) {
    if (fd_ != -1) {
        return true;
    }
    int fd = open(name_, O_RDONLY | O_CLOEXEC);
    static char path[PATH_MAX];
    if (fd == -1 || !adl_realpath_fd(fd, path)) {
        ADLOGE("open or get real path failed : %d, %s", fd, name_);
        return false;
    } else {
//        ADLOGI("open file(%s), get real path : %s", name_, path);
    }

    struct stat file_stat;
    if (fstat(fd, &file_stat) != 0) {
        ADLOGE("unable to stat file for the library \"%s\"", name_);
        return false;
    }

    fd_ = fd;
    real_path_ = path;
    file_size_ = file_stat.st_size;
//    ADLOGI("open file(%s) success[%d , %s, %d]",
//           name_, fd_, real_path_, file_size_);
    return true;
}

__END_DECLS
