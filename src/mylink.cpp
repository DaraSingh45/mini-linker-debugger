// mylink - a minimal static linker for x86-64 Linux.
//
// Input : ELF64 relocatable objects (.o from `gcc -c`) and static archives (.a)
// Output: a statically linked, non-PIE ELF64 executable (ET_EXEC).
//
// What it does
//   1. parses ELF section headers, symbol tables and RELA relocation tables
//   2. merges .text / .rodata / .data / .bss (+ .debug_* sections) of all inputs
//   3. resolves symbols across files (undefined / duplicate symbol errors,
//      weak symbols, COMMON symbols, archive member extraction)
//   4. applies x86-64 relocations (64, PC32, PLT32, 32, 32S, PC64)
//   5. writes program headers + section headers + .symtab so that readelf,
//      objdump, nm and the companion debugger (mydbg) understand the result.
//
// Not supported on purpose: shared libraries, dynamic linking, GOT/TLS,
// C++ exceptions (.eh_frame is dropped), init_array/ctors.

#include <sys/stat.h>

#include <algorithm>
#include <cstdlib>
#include <map>
#include <memory>
#include <set>

#include "elfreader.h"

namespace {

constexpr uint64_t PAGE = 0x1000;

uint64_t align_up(uint64_t v, uint64_t a) { return a > 1 ? (v + a - 1) / a * a : v; }

enum OutId { OUT_TEXT = 0, OUT_RODATA, OUT_DATA, OUT_BSS, OUT_FIXED };
enum { CLASS_SKIP = -1, CLASS_DEBUG = -2, CLASS_ERROR = -3 };

struct Options {
    std::string output = "a.out";
    std::string entry = "_start";
    uint64_t base = 0x400000;
    std::vector<std::string> inputs;
    std::vector<std::string> order = {"text", "rodata", "data"};
    bool map = false, verbose = false;
};

struct OutSection {
    std::string name;
    uint32_t type = SHT_PROGBITS;
    uint64_t flags = 0, align = 1, size = 0, addr = 0, fileoff = 0;
    std::vector<uint8_t> data;
    int shndx = 0;  // index in the output section header table (0 = not emitted)
};

struct InSection {
    int obj, idx, out;
    uint64_t off, size;
};

struct GSym {
    std::string name;
    bool defined = false, weak = false, common = false, strongRef = false, special = false;
    int obj = -1;
    uint16_t shndx = 0;
    uint64_t value = 0, size = 0, commonAlign = 1, commonOff = 0;
    uint8_t type = STT_NOTYPE;
    std::string firstRef;  // object that first referenced it while undefined
};

struct Object {
    std::string name;
    ElfFile elf;
    int symtab = -1;
    std::vector<Elf64_Sym> syms;
    std::vector<std::string> symNames;
    std::vector<int> secMap;  // input section index -> index into Linker::ins (or -1)
};

struct ArMember {
    std::string name;
    std::vector<uint8_t> bytes;
    std::vector<std::string> defs;  // global symbols this member defines
    bool loaded = false;
};
struct Archive {
    std::string path;
    std::vector<ArMember> members;
};

const char *reloc_name(uint32_t t) {
    switch (t) {
        case R_X86_64_NONE: return "R_X86_64_NONE";
        case R_X86_64_64: return "R_X86_64_64";
        case R_X86_64_PC32: return "R_X86_64_PC32";
        case R_X86_64_GOT32: return "R_X86_64_GOT32";
        case R_X86_64_PLT32: return "R_X86_64_PLT32";
        case R_X86_64_GOTPCREL: return "R_X86_64_GOTPCREL";
        case R_X86_64_32: return "R_X86_64_32";
        case R_X86_64_32S: return "R_X86_64_32S";
        case R_X86_64_PC64: return "R_X86_64_PC64";
        case R_X86_64_GOTPCRELX: return "R_X86_64_GOTPCRELX";
        case R_X86_64_REX_GOTPCRELX: return "R_X86_64_REX_GOTPCRELX";
        case R_X86_64_TPOFF32: return "R_X86_64_TPOFF32";
        default: return "<unknown>";
    }
}

class Linker {
public:
    explicit Linker(Options o) : opt(std::move(o)) {}
    int run();

private:
    Options opt;
    std::vector<std::unique_ptr<Object>> objs;
    std::vector<Archive> archives;
    std::map<std::string, GSym> globals;
    std::vector<std::string> errors;
    std::vector<OutSection> outs;
    std::vector<InSection> ins;
    std::map<std::string, int> debugOut;
    std::vector<int> debugIds;

    struct Seg {
        std::string key;
        std::vector<int> secs;
        uint32_t flags;
        uint64_t fileoff = 0, vaddr = 0, filesz = 0, memsz = 0;
    };
    std::vector<Seg> segs;

    void err(const std::string &m) { errors.push_back(m); }
    void log(const std::string &m) {
        if (opt.verbose) fprintf(stderr, "mylink: %s\n", m.c_str());
    }

    void addObject(const std::string &name, std::vector<uint8_t> bytes);
    void loadArchive(const std::string &path, std::vector<uint8_t> bytes);
    void resolveArchives();
    int classify(const Object &o, int si);
    void layout();
    void defineSpecials();
    uint64_t gsymAddr(const GSym &g);
    bool symAddr(Object &o, uint32_t si, uint64_t &out);
    void applyRelocations();
    void writeOutput();
    void printMap();
};

// --------------------------------------------------------------------------
// Step 1: read inputs, collect symbols
// --------------------------------------------------------------------------
void Linker::addObject(const std::string &name, std::vector<uint8_t> bytes) {
    auto o = std::make_unique<Object>();
    o->name = name;
    o->elf.load(name, std::move(bytes));
    if (o->elf.eh.e_type != ET_REL) throw ElfError(name + ": not a relocatable object file");
    for (size_t i = 0; i < o->elf.sections.size(); i++)
        if (o->elf.sections[i].hdr.sh_type == SHT_SYMTAB) o->symtab = (int)i;
    if (o->symtab < 0) throw ElfError(name + ": no symbol table");
    const Elf64_Shdr &sh = o->elf.sections[o->symtab].hdr;
    size_t n = sh.sh_size / sizeof(Elf64_Sym);
    o->syms.resize(n);
    if (n) memcpy(o->syms.data(), o->elf.data(o->symtab), n * sizeof(Elf64_Sym));
    for (auto &s : o->syms) o->symNames.push_back(o->elf.sym_name(sh, s.st_name));

    int oi = (int)objs.size();
    for (size_t i = 1; i < n; i++) {
        const Elf64_Sym &s = o->syms[i];
        uint8_t bind = ELF64_ST_BIND(s.st_info), type = ELF64_ST_TYPE(s.st_info);
        if (bind == STB_LOCAL || type == STT_SECTION || type == STT_FILE) continue;
        const std::string &nm = o->symNames[i];
        GSym &g = globals[nm];
        g.name = nm;
        if (s.st_shndx == SHN_UNDEF) {
            if (bind == STB_GLOBAL) g.strongRef = true;
            if (g.firstRef.empty()) g.firstRef = name;
            continue;
        }
        bool weak = (bind == STB_WEAK);
        if (s.st_shndx == SHN_COMMON) {
            if (g.defined && !g.common) continue;  // a real definition beats COMMON
            if (!g.defined) {
                g.defined = g.common = true;
                g.obj = oi;
                g.type = STT_OBJECT;
                g.size = s.st_size;
                g.commonAlign = s.st_value ? s.st_value : 1;
            } else {
                g.size = std::max<uint64_t>(g.size, s.st_size);
                g.commonAlign = std::max<uint64_t>(g.commonAlign, s.st_value);
            }
            continue;
        }
        if (g.defined && !g.common) {
            if (!g.weak && !weak) {
                err("duplicate symbol '" + nm + "': defined in " + objs[g.obj]->name + " and " + name);
                continue;
            }
            if (!(g.weak && !weak)) continue;  // keep existing (strong beats weak; first weak wins)
        }
        g.defined = true;
        g.common = false;
        g.weak = weak;
        g.obj = oi;
        g.shndx = s.st_shndx;
        g.value = s.st_value;
        g.size = s.st_size;
        g.type = type;
    }
    objs.push_back(std::move(o));
}

void Linker::loadArchive(const std::string &path, std::vector<uint8_t> bytes) {
    static const char MAGIC[] = "!<arch>\n";
    if (bytes.size() < 8 || memcmp(bytes.data(), MAGIC, 8) != 0)
        throw ElfError(path + ": not a static archive");
    Archive ar;
    ar.path = path;
    std::string longnames;
    size_t pos = 8;
    while (pos + 60 <= bytes.size()) {
        const char *h = (const char *)bytes.data() + pos;
        std::string nm(h, 16);
        size_t size = strtoull(std::string(h + 48, 10).c_str(), nullptr, 10);
        pos += 60;
        if (pos + size > bytes.size()) throw ElfError(path + ": truncated archive member");
        while (!nm.empty() && nm.back() == ' ') nm.pop_back();
        std::vector<uint8_t> body(bytes.begin() + pos, bytes.begin() + pos + size);
        pos += size + (size & 1);
        if (nm == "/" || nm == "/SYM64/") continue;  // symbol index: we scan members ourselves
        if (nm == "//") { longnames.assign(body.begin(), body.end()); continue; }
        if (nm[0] == '/' && nm.size() > 1) {  // GNU long name: "/offset"
            size_t off = strtoull(nm.c_str() + 1, nullptr, 10);
            size_t end = longnames.find('\n', off);
            nm = longnames.substr(off, end == std::string::npos ? std::string::npos : end - off);
        }
        if (!nm.empty() && nm.back() == '/') nm.pop_back();
        ArMember m;
        m.name = path + "(" + nm + ")";
        m.bytes = std::move(body);
        try {  // find which global symbols the member defines
            ElfFile e;
            e.load(m.name, m.bytes);
            for (size_t i = 0; i < e.sections.size(); i++) {
                if (e.sections[i].hdr.sh_type != SHT_SYMTAB) continue;
                const Elf64_Shdr &sh = e.sections[i].hdr;
                const Elf64_Sym *syms = (const Elf64_Sym *)e.data(i);
                for (size_t k = 1; k < sh.sh_size / sizeof(Elf64_Sym); k++)
                    if (ELF64_ST_BIND(syms[k].st_info) != STB_LOCAL && syms[k].st_shndx != SHN_UNDEF)
                        m.defs.push_back(e.sym_name(sh, syms[k].st_name));
            }
        } catch (const ElfError &) { continue; }  // not an ELF object: ignore member
        ar.members.push_back(std::move(m));
    }
    archives.push_back(std::move(ar));
}

// Pull in archive members that define a currently-undefined symbol, until nothing changes.
void Linker::resolveArchives() {
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto &ar : archives)
            for (auto &m : ar.members) {
                if (m.loaded) continue;
                bool needed = false;
                for (auto &d : m.defs) {
                    auto it = globals.find(d);
                    if (it != globals.end() && !it->second.defined && it->second.strongRef) { needed = true; break; }
                }
                if (!needed) continue;
                m.loaded = true;
                changed = true;
                log("extracting " + m.name);
                addObject(m.name, m.bytes);
            }
    }
}

// --------------------------------------------------------------------------
// Step 2: layout
// --------------------------------------------------------------------------
int Linker::classify(const Object &o, int si) {
    const ElfSection &s = o.elf.sections[si];
    const Elf64_Shdr &h = s.hdr;
    switch (h.sh_type) {
        case SHT_NULL: case SHT_SYMTAB: case SHT_STRTAB: case SHT_RELA: case SHT_GROUP:
        case SHT_NOTE: case SHT_X86_64_UNWIND:
            return CLASS_SKIP;
        case SHT_REL:
            err(o.name + ": SHT_REL relocations are not supported on x86-64");
            return CLASS_ERROR;
        default: break;
    }
    if (s.name.compare(0, 7, ".debug_") == 0) return CLASS_DEBUG;
    if (!(h.sh_flags & SHF_ALLOC)) return CLASS_SKIP;  // .comment, .note.*, ...
    if (s.name.compare(0, 9, ".eh_frame") == 0) return CLASS_SKIP;
    if (h.sh_flags & SHF_TLS) { err(o.name + ": thread-local storage is not supported (" + s.name + ")"); return CLASS_ERROR; }
    if (h.sh_type == SHT_INIT_ARRAY || h.sh_type == SHT_FINI_ARRAY || h.sh_type == SHT_PREINIT_ARRAY)
        fprintf(stderr, "mylink: warning: %s: %s is linked but never run (no runtime)\n", o.name.c_str(), s.name.c_str());
    if (h.sh_type == SHT_NOBITS) return OUT_BSS;
    if (h.sh_flags & SHF_EXECINSTR) return OUT_TEXT;
    if (h.sh_flags & SHF_WRITE) return OUT_DATA;
    return OUT_RODATA;
}

void Linker::layout() {
    outs.assign(OUT_FIXED, OutSection());
    outs[OUT_TEXT] = {".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR};
    outs[OUT_RODATA] = {".rodata", SHT_PROGBITS, SHF_ALLOC};
    outs[OUT_DATA] = {".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE};
    outs[OUT_BSS] = {".bss", SHT_NOBITS, SHF_ALLOC | SHF_WRITE};

    // 2a. assign every kept input section an (output section, offset)
    for (size_t oi = 0; oi < objs.size(); oi++) {
        Object &o = *objs[oi];
        o.secMap.assign(o.elf.sections.size(), -1);
        for (size_t si = 0; si < o.elf.sections.size(); si++) {
            int cls = classify(o, (int)si);
            if (cls == CLASS_SKIP || cls == CLASS_ERROR) continue;
            const Elf64_Shdr &h = o.elf.sections[si].hdr;
            int out = cls;
            if (cls == CLASS_DEBUG) {
                const std::string &nm = o.elf.sections[si].name;
                auto it = debugOut.find(nm);
                if (it == debugOut.end()) {
                    OutSection d;
                    d.name = nm;
                    outs.push_back(d);
                    it = debugOut.emplace(nm, (int)outs.size() - 1).first;
                    debugIds.push_back(it->second);
                }
                out = it->second;
            }
            OutSection &os = outs[out];
            uint64_t al = std::max<uint64_t>(h.sh_addralign, 1);
            uint64_t off = align_up(os.size, al);
            os.size = off + h.sh_size;
            os.align = std::max(os.align, al);
            if (h.sh_type != SHT_NOBITS) {
                os.data.resize(os.size, 0);
                memcpy(os.data.data() + off, o.elf.data(si), h.sh_size);
            }
            o.secMap[si] = (int)ins.size();
            ins.push_back({(int)oi, (int)si, out, off, h.sh_size});
        }
    }
    // 2b. COMMON symbols go to .bss
    for (auto &kv : globals) {
        GSym &g = kv.second;
        if (!(g.defined && g.common)) continue;
        OutSection &bss = outs[OUT_BSS];
        g.commonOff = align_up(bss.size, g.commonAlign);
        bss.size = g.commonOff + g.size;
        bss.align = std::max(bss.align, g.commonAlign);
    }
    // 2c. segments, in the user-selected order
    if (opt.base % PAGE) throw ElfError("--base must be page aligned (multiple of 0x1000)");
    for (auto &k : opt.order) {
        Seg s;
        s.key = k;
        if (k == "text") { s.secs = {OUT_TEXT}; s.flags = PF_R | PF_X; }
        else if (k == "rodata") { s.secs = {OUT_RODATA}; s.flags = PF_R; }
        else if (k == "data") { s.secs = {OUT_DATA, OUT_BSS}; s.flags = PF_R | PF_W; }
        else throw ElfError("unknown name in --section-order: '" + k + "' (use text,rodata,data)");
        uint64_t total = 0;
        for (int id : s.secs) total += outs[id].size;
        if (total) segs.push_back(s);
    }
    size_t phnum = segs.size() + 1;  // + PT_GNU_STACK
    uint64_t cursor = sizeof(Elf64_Ehdr) + phnum * sizeof(Elf64_Phdr);
    for (size_t i = 0; i < segs.size(); i++) {
        Seg &s = segs[i];
        uint64_t start = (i == 0) ? 0 : align_up(cursor, PAGE);
        s.fileoff = start;
        s.vaddr = opt.base + start;
        uint64_t fpos = (i == 0) ? cursor : start, mpos = fpos;
        for (int id : s.secs) {
            OutSection &os = outs[id];
            if (os.size == 0) { os.fileoff = fpos; os.addr = opt.base + fpos; continue; }
            if (os.type == SHT_NOBITS) {
                mpos = align_up(mpos, os.align);
                os.fileoff = fpos;
                os.addr = opt.base + mpos;
                mpos += os.size;
            } else {
                fpos = align_up(fpos, os.align);
                os.fileoff = fpos;
                os.addr = opt.base + fpos;
                fpos += os.size;
                mpos = fpos;
            }
        }
        s.filesz = fpos - start;
        s.memsz = mpos - start;
        cursor = fpos;
    }
    // 2d. non-allocated debug sections are appended after the loadable part
    for (int id : debugIds) {
        outs[id].fileoff = cursor;
        outs[id].addr = 0;  // so that relocations against them yield plain section offsets
        cursor += outs[id].size;
    }
}

// Symbols such as _end that the linker itself defines (only if the program uses them).
void Linker::defineSpecials() {
    struct S { const char *name; uint64_t val; };
    uint64_t textEnd = outs[OUT_TEXT].addr + outs[OUT_TEXT].size;
    uint64_t dataEnd = outs[OUT_DATA].size ? outs[OUT_DATA].addr + outs[OUT_DATA].size : outs[OUT_BSS].addr;
    uint64_t bssEnd = outs[OUT_BSS].addr + outs[OUT_BSS].size;
    S list[] = {{"__executable_start", opt.base}, {"_etext", textEnd}, {"etext", textEnd},
                {"_edata", dataEnd}, {"edata", dataEnd}, {"__bss_start", dataEnd},
                {"_end", bssEnd}, {"end", bssEnd}};
    for (const char *n : {"_edata", "__bss_start", "_end"}) globals[n].name = n;  // like GNU ld, always provided
    for (auto &s : list) {
        auto it = globals.find(s.name);
        if (it == globals.end() || it->second.defined) continue;
        GSym &g = it->second;
        g.defined = g.special = true;
        g.shndx = SHN_ABS;
        g.value = s.val;
    }
}

uint64_t Linker::gsymAddr(const GSym &g) {
    if (g.common) return outs[OUT_BSS].addr + g.commonOff;
    if (g.shndx == SHN_ABS) return g.value;
    Object &o = *objs[g.obj];
    int m = g.shndx < o.secMap.size() ? o.secMap[g.shndx] : -1;
    if (m < 0) { err(o.name + ": symbol '" + g.name + "' is defined in a discarded section"); return 0; }
    return outs[ins[m].out].addr + ins[m].off + g.value;
}

// Final address ("S" in relocation formulas) of symbol #si of object o.
bool Linker::symAddr(Object &o, uint32_t si, uint64_t &out) {
    if (si >= o.syms.size()) { err(o.name + ": relocation refers to bad symbol index"); return false; }
    if (si == 0) { out = 0; return true; }
    const Elf64_Sym &s = o.syms[si];
    const std::string &nm = o.symNames[si];
    uint8_t bind = ELF64_ST_BIND(s.st_info);
    if (s.st_shndx == SHN_UNDEF || bind != STB_LOCAL) {
        auto it = globals.find(nm);
        if (it == globals.end() || !it->second.defined) {
            out = 0;
            return bind == STB_WEAK;  // undefined weak -> 0; strong ones were reported already
        }
        out = gsymAddr(it->second);
        return true;
    }
    if (s.st_shndx == SHN_ABS) { out = s.st_value; return true; }
    int m = s.st_shndx < o.secMap.size() ? o.secMap[s.st_shndx] : -1;
    if (m < 0) {
        err(o.name + ": relocation against symbol '" + nm + "' in a section that was discarded");
        return false;
    }
    out = outs[ins[m].out].addr + ins[m].off + s.st_value;
    return true;
}

// --------------------------------------------------------------------------
// Step 3: relocations
// --------------------------------------------------------------------------
void Linker::applyRelocations() {
    for (auto &op : objs) {
        Object &o = *op;
        for (size_t ri = 0; ri < o.elf.sections.size(); ri++) {
            const Elf64_Shdr &rh = o.elf.sections[ri].hdr;
            if (rh.sh_type != SHT_RELA) continue;
            int m = rh.sh_info < o.secMap.size() ? o.secMap[rh.sh_info] : -1;
            if (m < 0) continue;  // relocations for a section we dropped (.eh_frame ...)
            InSection &is = ins[m];
            OutSection &os = outs[is.out];
            if (os.type == SHT_NOBITS) continue;
            const Elf64_Rela *rel = (const Elf64_Rela *)o.elf.data(ri);
            size_t n = rh.sh_size / sizeof(Elf64_Rela);
            for (size_t k = 0; k < n; k++) {
                uint32_t type = ELF64_R_TYPE(rel[k].r_info), si = ELF64_R_SYM(rel[k].r_info);
                int64_t A = rel[k].r_addend;
                uint64_t where = rel[k].r_offset;
                std::string at = o.name + " (" + o.elf.sections[rh.sh_info].name + "+0x" +
                                 [&] { char b[32]; snprintf(b, sizeof b, "%lx", where); return std::string(b); }() + ")";
                if (type == R_X86_64_NONE) continue;
                uint64_t width = (type == R_X86_64_64 || type == R_X86_64_PC64) ? 8 : 4;
                if (where + width > is.size) { err(at + ": relocation outside section"); continue; }
                uint64_t S;
                if (!symAddr(o, si, S)) continue;
                uint8_t *loc = os.data.data() + is.off + where;
                uint64_t P = os.addr + is.off + where;
                auto fail = [&](const char *why) {
                    err(at + ": relocation " + reloc_name(type) + " " + why + " (symbol '" + o.symNames[si] + "')");
                };
                switch (type) {
                    case R_X86_64_64: { uint64_t v = S + A; memcpy(loc, &v, 8); break; }
                    case R_X86_64_PC64: { uint64_t v = S + A - P; memcpy(loc, &v, 8); break; }
                    case R_X86_64_PC32:
                    case R_X86_64_PLT32: {  // static link: PLT32 behaves exactly like PC32
                        int64_t v = (int64_t)(S + A - P);
                        if (v < INT32_MIN || v > INT32_MAX) { fail("overflows 32 bits"); break; }
                        int32_t w = (int32_t)v; memcpy(loc, &w, 4); break;
                    }
                    case R_X86_64_32: {
                        uint64_t v = S + A;
                        if (v > UINT32_MAX) { fail("overflows 32 bits (use a lower --base or compile with -mcmodel=small)"); break; }
                        uint32_t w = (uint32_t)v; memcpy(loc, &w, 4); break;
                    }
                    case R_X86_64_32S: {
                        int64_t v = (int64_t)(S + A);
                        if (v < INT32_MIN || v > INT32_MAX) { fail("overflows signed 32 bits"); break; }
                        int32_t w = (int32_t)v; memcpy(loc, &w, 4); break;
                    }
                    case R_X86_64_GOTPCREL: case R_X86_64_GOTPCRELX: case R_X86_64_REX_GOTPCRELX: case R_X86_64_GOT32:
                        fail("needs a GOT (not supported) - recompile with -fno-pic -fno-pie");
                        break;
                    default:
                        fail("is not supported");
                }
            }
        }
    }
}

// --------------------------------------------------------------------------
// Step 4: write the executable
// --------------------------------------------------------------------------
void Linker::writeOutput() {
    auto ge = globals.find(opt.entry);
    if (ge == globals.end() || !ge->second.defined) {
        err("entry symbol '" + opt.entry + "' is not defined");
        return;
    }
    uint64_t entry = gsymAddr(ge->second);
    if (!errors.empty()) return;

    // section header table layout: [0]=null, alloc sections, debug sections, symtab, strtab, shstrtab
    std::vector<int> shOrder;
    int next = 1;
    for (int id : {(int)OUT_TEXT, (int)OUT_RODATA, (int)OUT_DATA, (int)OUT_BSS})
        if (outs[id].size) { outs[id].shndx = next++; shOrder.push_back(id); }
    for (int id : debugIds) { outs[id].shndx = next++; shOrder.push_back(id); }
    int symtabIdx = next++, strtabIdx = next++, shstrIdx = next++;

    // symbol table (locals first, then globals)
    std::vector<Elf64_Sym> syms(1);
    std::string strtab(1, '\0');
    auto addSym = [&](const std::string &nm, uint8_t info, uint16_t shndx, uint64_t val, uint64_t size) {
        Elf64_Sym s{};
        s.st_name = (uint32_t)strtab.size();
        strtab += nm;
        strtab.push_back('\0');
        s.st_info = info;
        s.st_shndx = shndx;
        s.st_value = val;
        s.st_size = size;
        syms.push_back(s);
    };
    for (auto &op : objs) {
        Object &o = *op;
        for (size_t i = 1; i < o.syms.size(); i++) {
            const Elf64_Sym &s = o.syms[i];
            uint8_t type = ELF64_ST_TYPE(s.st_info);
            if (ELF64_ST_BIND(s.st_info) != STB_LOCAL || type == STT_SECTION || type == STT_FILE) continue;
            if (o.symNames[i].empty() || s.st_shndx == SHN_UNDEF || s.st_shndx >= SHN_LORESERVE) continue;
            int m = o.secMap[s.st_shndx];
            if (m < 0 || outs[ins[m].out].shndx == 0 || ins[m].out >= OUT_FIXED) continue;
            addSym(o.symNames[i], ELF64_ST_INFO(STB_LOCAL, type), outs[ins[m].out].shndx,
                   outs[ins[m].out].addr + ins[m].off + s.st_value, s.st_size);
        }
    }
    size_t firstGlobal = syms.size();
    for (auto &kv : globals) {
        const GSym &g = kv.second;
        if (!g.defined) continue;
        uint16_t shndx;
        if (g.common) shndx = outs[OUT_BSS].shndx;
        else if (g.special) {  // attach to a section the way GNU ld does (nm shows B/D/T)
            int id = g.name == "_edata" || g.name == "edata" ? OUT_DATA
                   : g.name == "_etext" || g.name == "etext" ? OUT_TEXT
                   : g.name == "__executable_start" ? -1 : OUT_BSS;
            shndx = (id >= 0 && outs[id].shndx) ? outs[id].shndx : SHN_ABS;
        }
        else if (g.shndx == SHN_ABS) shndx = SHN_ABS;
        else {
            int m = objs[g.obj]->secMap[g.shndx];
            if (m < 0 || ins[m].out >= OUT_FIXED) continue;
            shndx = outs[ins[m].out].shndx;
        }
        addSym(g.name, ELF64_ST_INFO(g.weak ? STB_WEAK : STB_GLOBAL, g.type), shndx, gsymAddr(g), g.size);
    }

    // file image
    size_t phnum = segs.size() + 1;
    std::vector<uint8_t> f(sizeof(Elf64_Ehdr) + phnum * sizeof(Elf64_Phdr), 0);
    auto place = [&](uint64_t off, const std::vector<uint8_t> &d) {
        if (f.size() < off + d.size()) f.resize(off + d.size(), 0);
        if (!d.empty()) memcpy(f.data() + off, d.data(), d.size());
    };
    for (int id : shOrder)
        if (outs[id].type != SHT_NOBITS) place(outs[id].fileoff, outs[id].data);
    for (auto &s : segs)
        if (f.size() < s.fileoff + s.filesz) f.resize(s.fileoff + s.filesz, 0);

    auto append = [&](const void *p, size_t n, uint64_t al) {
        uint64_t off = align_up(f.size(), al);
        f.resize(off + n, 0);
        memcpy(f.data() + off, p, n);
        return off;
    };
    uint64_t symtabOff = append(syms.data(), syms.size() * sizeof(Elf64_Sym), 8);
    uint64_t strtabOff = append(strtab.data(), strtab.size(), 1);

    std::string shstr(1, '\0');
    auto shname = [&](const std::string &n) { uint32_t o = (uint32_t)shstr.size(); shstr += n; shstr.push_back('\0'); return o; };
    std::vector<Elf64_Shdr> sh(next);
    for (int id : shOrder) {
        const OutSection &os = outs[id];
        Elf64_Shdr &h = sh[os.shndx];
        h.sh_name = shname(os.name);
        h.sh_type = os.type;
        h.sh_flags = os.flags;
        h.sh_addr = os.addr;
        h.sh_offset = os.fileoff;
        h.sh_size = os.size;
        h.sh_addralign = os.align;
    }
    sh[symtabIdx] = {shname(".symtab"), SHT_SYMTAB, 0, 0, symtabOff, syms.size() * sizeof(Elf64_Sym),
                     (uint32_t)strtabIdx, (uint32_t)firstGlobal, 8, sizeof(Elf64_Sym)};
    sh[strtabIdx] = {shname(".strtab"), SHT_STRTAB, 0, 0, strtabOff, strtab.size(), 0, 0, 1, 0};
    uint32_t shstrName = shname(".shstrtab");
    uint64_t shstrOff = append(shstr.data(), shstr.size(), 1);
    sh[shstrIdx] = {shstrName, SHT_STRTAB, 0, 0, shstrOff, shstr.size(), 0, 0, 1, 0};
    uint64_t shoff = append(sh.data(), sh.size() * sizeof(Elf64_Shdr), 8);

    // ELF header + program headers
    Elf64_Ehdr eh{};
    memcpy(eh.e_ident, ELFMAG, SELFMAG);
    eh.e_ident[EI_CLASS] = ELFCLASS64;
    eh.e_ident[EI_DATA] = ELFDATA2LSB;
    eh.e_ident[EI_VERSION] = EV_CURRENT;
    eh.e_ident[EI_OSABI] = ELFOSABI_SYSV;
    eh.e_type = ET_EXEC;
    eh.e_machine = EM_X86_64;
    eh.e_version = EV_CURRENT;
    eh.e_entry = entry;
    eh.e_phoff = sizeof(Elf64_Ehdr);
    eh.e_shoff = shoff;
    eh.e_ehsize = sizeof(Elf64_Ehdr);
    eh.e_phentsize = sizeof(Elf64_Phdr);
    eh.e_phnum = (uint16_t)phnum;
    eh.e_shentsize = sizeof(Elf64_Shdr);
    eh.e_shnum = (uint16_t)sh.size();
    eh.e_shstrndx = (uint16_t)shstrIdx;
    memcpy(f.data(), &eh, sizeof eh);
    std::vector<Elf64_Phdr> ph;
    for (auto &s : segs) {
        Elf64_Phdr p{};
        p.p_type = PT_LOAD;
        p.p_flags = s.flags;
        p.p_offset = s.fileoff;
        p.p_vaddr = p.p_paddr = s.vaddr;
        p.p_filesz = s.filesz;
        p.p_memsz = s.memsz;
        p.p_align = PAGE;
        ph.push_back(p);
    }
    Elf64_Phdr st{};
    st.p_type = PT_GNU_STACK;  // non-executable stack
    st.p_flags = PF_R | PF_W;
    st.p_align = 16;
    ph.push_back(st);
    memcpy(f.data() + sizeof(Elf64_Ehdr), ph.data(), ph.size() * sizeof(Elf64_Phdr));

    FILE *fp = fopen(opt.output.c_str(), "wb");
    if (!fp) { err("cannot write '" + opt.output + "'"); return; }
    fwrite(f.data(), 1, f.size(), fp);
    fclose(fp);
    chmod(opt.output.c_str(), 0755);
    log("wrote " + opt.output + " (" + std::to_string(f.size()) + " bytes), entry 0x" + [&] { char b[32]; snprintf(b, sizeof b, "%lx", entry); return std::string(b); }());
}

void Linker::printMap() {
    printf("Link map for %s (entry %s)\n\nOutput sections:\n", opt.output.c_str(), opt.entry.c_str());
    printf("  %-14s %-18s %-10s %s\n", "section", "address", "size", "file offset");
    for (int id : {(int)OUT_TEXT, (int)OUT_RODATA, (int)OUT_DATA, (int)OUT_BSS}) {
        const OutSection &os = outs[id];
        if (!os.size) continue;
        printf("  %-14s 0x%016lx 0x%-8lx 0x%lx\n", os.name.c_str(), os.addr, os.size, os.fileoff);
        for (auto &is : ins)
            if (is.out == id)
                printf("      0x%016lx 0x%-6lx %s(%s)\n", os.addr + is.off, is.size,
                       objs[is.obj]->name.c_str(), objs[is.obj]->elf.sections[is.idx].name.c_str());
    }
    printf("\nGlobal symbols:\n");
    std::vector<std::pair<uint64_t, std::string>> v;
    for (auto &kv : globals)
        if (kv.second.defined) v.push_back({gsymAddr(kv.second), kv.first});
    std::sort(v.begin(), v.end());
    for (auto &p : v) printf("  0x%016lx  %s\n", p.first, p.second.c_str());
}

int Linker::run() {
    if (opt.inputs.empty()) { fprintf(stderr, "mylink: no input files\n"); return 1; }
    try {
        for (auto &in : opt.inputs) {
            auto bytes = read_whole_file(in);
            if (bytes.size() >= 8 && memcmp(bytes.data(), "!<arch>\n", 8) == 0) loadArchive(in, std::move(bytes));
            else addObject(in, std::move(bytes));
        }
        resolveArchives();
        for (auto &kv : globals) {
            const GSym &g = kv.second;
            static const std::set<std::string> linkerDefined = {
                "__executable_start", "_etext", "etext", "_edata", "edata", "__bss_start", "_end", "end"};
            if (!g.defined && g.strongRef && !linkerDefined.count(g.name))
                err(g.firstRef + ": undefined reference to '" + g.name + "'");
        }
        if (errors.empty()) {
            layout();
            defineSpecials();
            applyRelocations();
            if (errors.empty()) writeOutput();
            if (errors.empty() && opt.map) printMap();
        }
    } catch (const ElfError &e) {
        err(e.what());
    }
    for (auto &e : errors) fprintf(stderr, "mylink: error: %s\n", e.c_str());
    return errors.empty() ? 0 : 1;
}

void usage() {
    puts("usage: mylink [options] file.o|lib.a ... -o output\n"
         "  -o FILE                 output file (default a.out)\n"
         "  -e SYMBOL               entry symbol (default _start)\n"
         "  --base=ADDR             load address, page aligned (default 0x400000)\n"
         "  --section-order=LIST    order of segments in memory, e.g. rodata,text,data\n"
         "  --map                   print a link map to stdout\n"
         "  -v                      verbose");
}

}  // namespace

int main(int argc, char **argv) {
    Options o;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "-o" && i + 1 < argc) o.output = argv[++i];
        else if (a == "-e" && i + 1 < argc) o.entry = argv[++i];
        else if (a.compare(0, 7, "--base=") == 0) o.base = strtoull(a.c_str() + 7, nullptr, 0);
        else if (a.compare(0, 16, "--section-order=") == 0) {
            o.order.clear();
            std::string list = a.substr(16), tok;
            for (char c : list + ",") { if (c == ',') { if (!tok.empty()) o.order.push_back(tok); tok.clear(); } else tok += c; }
        }
        else if (a == "--map") o.map = true;
        else if (a == "-v") o.verbose = true;
        else if (a == "-h" || a == "--help") { usage(); return 0; }
        else if (!a.empty() && a[0] == '-') { fprintf(stderr, "mylink: unknown option '%s'\n", a.c_str()); return 1; }
        else o.inputs.push_back(a);
    }
    return Linker(std::move(o)).run();
}
