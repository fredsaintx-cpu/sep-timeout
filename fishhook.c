// Minimal fishhook implementation for iOS
#include "fishhook.h"
#include <string.h>
#include <stdlib.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <dlfcn.h>

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

struct rebindings_entry {
    struct rebinding *rebindings;
    size_t rebindings_nel;
    struct rebindings_entry *next;
};
static struct rebindings_entry *rebindings_head;

static int prepend_rebindings(struct rebindings_entry **head,
                               struct rebinding rebindings[], size_t nel) {
    struct rebindings_entry *entry = malloc(sizeof(struct rebindings_entry));
    if (!entry) return -1;
    entry->rebindings = malloc(sizeof(struct rebinding) * nel);
    if (!entry->rebindings) { free(entry); return -1; }
    memcpy(entry->rebindings, rebindings, sizeof(struct rebinding) * nel);
    entry->rebindings_nel = nel;
    entry->next = *head;
    *head = entry;
    return 0;
}

static void perform_rebinding_with_section(struct rebindings_entry *entry,
                                            section_t *section, intptr_t slide,
                                            nlist_t *symtab, char *strtab,
                                            uint32_t *indirect_symtab) {
    uint32_t *indices = indirect_symtab + section->reserved1;
    void **bindings = (void **)((uintptr_t)slide + section->addr);
    for (uint32_t i = 0; i < section->size / sizeof(void *); i++) {
        uint32_t idx = indices[i];
        if (idx == INDIRECT_SYMBOL_ABS || idx == INDIRECT_SYMBOL_LOCAL) continue;
        char *name = strtab + symtab[idx].n_un.n_strx;
        struct rebindings_entry *cur = entry;
        while (cur) {
            for (size_t j = 0; j < cur->rebindings_nel; j++) {
                if (strcmp(name, cur->rebindings[j].name) == 0) {
                    if (cur->rebindings[j].replaced)
                        *cur->rebindings[j].replaced = bindings[i];
                    bindings[i] = cur->rebindings[j].replacement;
                    goto next;
                }
            }
            cur = cur->next;
        }
        next:;
    }
}

static void rebind_symbols_for_image(struct rebindings_entry *entry,
                                      const struct mach_header *header, intptr_t slide) {
    Dl_info info;
    if (dladdr(header, &info) == 0) return;
    uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
    segment_command_t *linkedit = NULL;
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;
    for (uint32_t i = 0; i < header->ncmds; i++, cur += ((struct load_command *)cur)->cmdsize) {
        struct load_command *lc = (struct load_command *)cur;
        switch (lc->cmd) {
            case LC_SEGMENT_ARCH_DEPENDENT:
                if (strcmp(((segment_command_t *)lc)->segname, "__LINKEDIT") == 0)
                    linkedit = (segment_command_t *)lc;
                break;
            case LC_SYMTAB: symtab_cmd = (struct symtab_command *)lc; break;
            case LC_DYSYMTAB: dysymtab_cmd = (struct dysymtab_command *)lc; break;
        }
    }
    if (!linkedit || !symtab_cmd || !dysymtab_cmd) return;
    uintptr_t base = slide + linkedit->vmaddr - linkedit->fileoff;
    nlist_t *symtab = (nlist_t *)(base + symtab_cmd->symoff);
    char *strtab = (char *)(base + symtab_cmd->stroff);
    uint32_t *indirect = (uint32_t *)(base + dysymtab_cmd->indirectsymoff);
    cur = (uintptr_t)header + sizeof(mach_header_t);
    for (uint32_t i = 0; i < header->ncmds; i++, cur += ((struct load_command *)cur)->cmdsize) {
        struct load_command *lc = (struct load_command *)cur;
        if (lc->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
            segment_command_t *seg = (segment_command_t *)cur;
            section_t *sect = (section_t *)((uintptr_t)seg + sizeof(segment_command_t));
            for (uint32_t j = 0; j < seg->nsects; j++) {
                if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS ||
                    (sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS)
                    perform_rebinding_with_section(entry, sect, slide, symtab, strtab, indirect);
                sect++;
            }
        }
    }
}

int rebind_symbols_image(void *header, intptr_t slide,
                          struct rebinding rebindings[], size_t rebindings_nel) {
    struct rebindings_entry *entry = NULL;
    int ret = prepend_rebindings(&entry, rebindings, rebindings_nel);
    if (ret < 0) return ret;
    rebind_symbols_for_image(entry, (const struct mach_header *)header, slide);
    free(entry->rebindings); free(entry);
    return 0;
}

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {
    struct rebindings_entry *entry = NULL;
    int ret = prepend_rebindings(&entry, rebindings, rebindings_nel);
    if (ret < 0) return ret;
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++)
        rebind_symbols_for_image(entry, _dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
    free(entry->rebindings); free(entry);
    return 0;
}
