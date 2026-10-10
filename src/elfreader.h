// elfreader.h - tiny ELF64 (x86-64, little endian) file reader shared by the
// linker (mylink) and the debugger (mydbg).
#pragma once
#include <elf.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

struct ElfError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

inline std::vector<uint8_t> read_whole_file(const std::string &path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw ElfError("cannot open '" + path + "'");
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());
}

struct ElfSection {
    std::string name;
    Elf64_Shdr hdr;
};

class ElfFile {
public:
    std::string path;
    std::vector<uint8_t> bytes;
    Elf64_Ehdr eh{};
    std::vector<ElfSection> sections;

    void load(const std::string &p, std::vector<uint8_t> b) {
        path = p;
        bytes = std::move(b);
        if (bytes.size() < sizeof(Elf64_Ehdr) || memcmp(bytes.data(), ELFMAG, SELFMAG) != 0)
            throw ElfError(p + ": not an ELF file");
        memcpy(&eh, bytes.data(), sizeof eh);
        if (eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_ident[EI_DATA] != ELFDATA2LSB ||
            eh.e_machine != EM_X86_64)
            throw ElfError(p + ": only ELF64 little-endian x86-64 files are supported");
        if (eh.e_shnum == 0) return;  // no section table
        if (eh.e_shentsize != sizeof(Elf64_Shdr) ||
            eh.e_shoff + (uint64_t)eh.e_shnum * sizeof(Elf64_Shdr) > bytes.size())
            throw ElfError(p + ": corrupt section header table");
        sections.resize(eh.e_shnum);
        for (unsigned i = 0; i < eh.e_shnum; i++)
            memcpy(&sections[i].hdr, bytes.data() + eh.e_shoff + i * sizeof(Elf64_Shdr),
                   sizeof(Elf64_Shdr));
        if (eh.e_shstrndx >= sections.size()) throw ElfError(p + ": bad e_shstrndx");
        const Elf64_Shdr &str = sections[eh.e_shstrndx].hdr;
        for (auto &s : sections) {
            if (s.hdr.sh_type != SHT_NOBITS &&
                (s.hdr.sh_offset > bytes.size() || s.hdr.sh_size > bytes.size() - s.hdr.sh_offset))
                throw ElfError(p + ": section extends past end of file");
            if (s.hdr.sh_name < str.sh_size)
                s.name = (const char *)bytes.data() + str.sh_offset + s.hdr.sh_name;
        }
    }

    // Pointer to a section's raw bytes (nullptr for NOBITS).
    const uint8_t *data(size_t idx) const {
        if (idx >= sections.size() || sections[idx].hdr.sh_type == SHT_NOBITS) return nullptr;
        return bytes.data() + sections[idx].hdr.sh_offset;
    }
    int find(const std::string &name) const {
        for (size_t i = 0; i < sections.size(); i++)
            if (sections[i].name == name) return (int)i;
        return -1;
    }
    // Name of a symbol, given its symbol table section header and st_name.
    const char *sym_name(const Elf64_Shdr &symtab, uint32_t off) const {
        const Elf64_Shdr &st = sections.at(symtab.sh_link).hdr;
        if (off >= st.sh_size) return "";
        return (const char *)bytes.data() + st.sh_offset + off;
    }
};
