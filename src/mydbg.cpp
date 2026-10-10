// mydbg - a tiny source-level debugger for x86-64 Linux (non-PIE, ET_EXEC binaries).
//
//   * ptrace based: launch, int3 breakpoints, single-step, registers, memory
//   * DWARF .debug_line parser (versions 2-5)  -> `break file.c:12`, source display
//   * DWARF .debug_info parser                 -> print locals / params / globals by name
//   * frame-pointer based backtrace            -> `bt`
//
// Works best on binaries built with  gcc -g -O0 -fno-omit-frame-pointer  (-O0 is the default).

#include <errno.h>
#include <signal.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <functional>
#include <iostream>
#include <map>
#include <set>
#include <sstream>

#include "elfreader.h"

namespace {

// ---------------------------------------------------------------------------
// Little-endian byte reader with LEB128 support
// ---------------------------------------------------------------------------
struct Reader {
    const uint8_t *b;
    size_t size, pos;
    Reader(const uint8_t *p, size_t n, size_t at = 0) : b(p), size(n), pos(at) {}
    bool eof() const { return pos >= size; }
    void need(size_t n) const { if (pos + n > size) throw ElfError("DWARF: read past end of section"); }
    uint8_t u8() { need(1); return b[pos++]; }
    uint16_t u16() { return (uint16_t)un(2); }
    uint32_t u32() { return (uint32_t)un(4); }
    uint64_t u64() { return un(8); }
    uint64_t un(int n) { need(n); uint64_t v = 0; for (int i = 0; i < n; i++) v |= (uint64_t)b[pos + i] << (8 * i); pos += n; return v; }
    uint64_t uleb() { uint64_t r = 0; int sh = 0; for (;;) { uint8_t c = u8(); if (sh < 64) r |= (uint64_t)(c & 0x7f) << sh; sh += 7; if (!(c & 0x80)) return r; } }
    int64_t sleb() {
        int64_t r = 0; int sh = 0; uint8_t c;
        do { c = u8(); if (sh < 64) r |= (int64_t)(c & 0x7f) << sh; sh += 7; } while (c & 0x80);
        if (sh < 64 && (c & 0x40)) r |= -((int64_t)1 << sh);
        return r;
    }
    std::string cstr() { std::string s; for (;;) { char c = (char)u8(); if (!c) return s; s += c; } }
};

struct Sec {
    const uint8_t *p = nullptr;
    size_t n = 0;
    const char *str(uint64_t off) const { return (p && off < n) ? (const char *)p + off : ""; }
};

std::string base_name(const std::string &p) { size_t i = p.rfind('/'); return i == std::string::npos ? p : p.substr(i + 1); }

// ---------------------------------------------------------------------------
// .debug_line  (address <-> source line)
// ---------------------------------------------------------------------------
struct LineRow {
    uint64_t addr;
    int file;
    uint32_t line;
    bool stmt, end;
};

struct LineTable {
    std::vector<std::string> files;  // full path of each file referenced by the rows
    std::vector<LineRow> rows;       // sorted by address

    int fileId(const std::string &p) {
        for (size_t i = 0; i < files.size(); i++) if (files[i] == p) return (int)i;
        files.push_back(p);
        return (int)files.size() - 1;
    }

    // Parse a DW_FORM_* value from a DWARF-5 directory/file entry
    struct Ent { std::string path; uint64_t dir = 0; };
    static void skipOrRead(Reader &r, uint64_t form, bool dw64, const Sec &str, const Sec &lstr, std::string *s, uint64_t *u) {
        switch (form) {
            case 0x08: { std::string v = r.cstr(); if (s) *s = v; break; }                                  // string
            case 0x1f: { uint64_t o = r.un(dw64 ? 8 : 4); if (s) *s = lstr.str(o); break; }                 // line_strp
            case 0x0e: { uint64_t o = r.un(dw64 ? 8 : 4); if (s) *s = str.str(o); break; }                  // strp
            case 0x0f: { uint64_t v = r.uleb(); if (u) *u = v; break; }                                    // udata
            case 0x0b: { uint64_t v = r.u8(); if (u) *u = v; break; }                                      // data1
            case 0x05: { uint64_t v = r.u16(); if (u) *u = v; break; }                                     // data2
            case 0x06: { uint64_t v = r.u32(); if (u) *u = v; break; }                                     // data4
            case 0x07: { uint64_t v = r.u64(); if (u) *u = v; break; }                                     // data8
            case 0x1e: r.pos += 16; break;                                                                 // data16 (MD5)
            case 0x09: { uint64_t n = r.uleb(); r.pos += n; break; }                                       // block
            default: throw ElfError("unsupported form in line table header");
        }
    }

    void parse(const Sec &line, const Sec &str, const Sec &lstr) {
        Reader r(line.p, line.n);
        while (!r.eof()) {
            uint64_t len = r.u32();
            bool dw64 = false;
            if (len == 0xffffffff) { dw64 = true; len = r.u64(); }
            size_t unitEnd = r.pos + len;
            uint16_t ver = r.u16();
            if (ver < 2 || ver > 5) throw ElfError("unsupported .debug_line version " + std::to_string(ver));
            if (ver >= 5) { r.u8(); r.u8(); }  // address_size, segment_selector_size
            uint64_t hlen = dw64 ? r.u64() : r.u32();
            size_t progStart = r.pos + hlen;
            uint8_t minInst = r.u8();
            if (ver >= 4) r.u8();  // max ops per instruction
            bool defStmt = r.u8();
            int8_t lineBase = (int8_t)r.u8();
            uint8_t lineRange = r.u8(), opBase = r.u8();
            std::vector<uint8_t> stdLen(opBase ? opBase - 1 : 0);
            for (auto &l : stdLen) l = r.u8();

            std::vector<std::string> dirs;
            std::vector<Ent> fl;  // index == DWARF file number
            if (ver >= 5) {
                for (int pass = 0; pass < 2; pass++) {  // pass 0: directories, pass 1: files
                    int fmtCount = r.u8();
                    std::vector<std::pair<uint64_t, uint64_t>> fmt;
                    for (int i = 0; i < fmtCount; i++) { uint64_t t = r.uleb(), f = r.uleb(); fmt.push_back({t, f}); }
                    uint64_t cnt = r.uleb();
                    for (uint64_t i = 0; i < cnt; i++) {
                        Ent e;
                        for (auto &p : fmt) {
                            std::string s; uint64_t u = 0;
                            skipOrRead(r, p.second, dw64, str, lstr, &s, &u);
                            if (p.first == 1) e.path = s;        // DW_LNCT_path
                            else if (p.first == 2) e.dir = u;    // DW_LNCT_directory_index
                        }
                        if (pass == 0) dirs.push_back(e.path); else fl.push_back(e);
                    }
                }
            } else {
                dirs.push_back("");  // index 0 = compilation directory (unknown here)
                for (;;) { std::string d = r.cstr(); if (d.empty()) break; dirs.push_back(d); }
                fl.push_back({"", 0});  // file numbers start at 1
                for (;;) {
                    std::string f = r.cstr();
                    if (f.empty()) break;
                    Ent e; e.path = f; e.dir = r.uleb(); r.uleb(); r.uleb();
                    fl.push_back(e);
                }
            }
            std::vector<int> ids(fl.size());
            for (size_t i = 0; i < fl.size(); i++) {
                std::string p = fl[i].path;
                if (!p.empty() && p[0] != '/') {
                    std::string d = fl[i].dir < dirs.size() ? dirs[fl[i].dir] : "";
                    if (!d.empty() && d[0] != '/' && !dirs.empty() && !dirs[0].empty() && ver >= 5) d = dirs[0] + "/" + d;
                    if (fl[i].dir == 0 && ver >= 5 && !dirs.empty()) d = dirs[0];
                    if (!d.empty()) p = d + "/" + p;
                }
                ids[i] = fileId(p);
            }

            // run the line-number state machine
            r.pos = progStart;
            uint64_t addr = 0; int file = 1; int64_t ln = 1; bool stmt = defStmt;
            auto reset = [&] { addr = 0; file = 1; ln = 1; stmt = defStmt; };
            auto emit = [&](bool end) {
                int id = (size_t)file < ids.size() ? ids[file] : -1;
                rows.push_back({addr, id, (uint32_t)ln, stmt, end});
            };
            while (r.pos < unitEnd) {
                uint8_t op = r.u8();
                if (op >= opBase) {
                    uint8_t adj = op - opBase;
                    addr += (uint64_t)(adj / lineRange) * minInst;
                    ln += lineBase + (adj % lineRange);
                    emit(false);
                } else if (op == 0) {
                    uint64_t elen = r.uleb();
                    size_t next = r.pos + elen;
                    uint8_t sub = r.u8();
                    if (sub == 1) { emit(true); reset(); }
                    else if (sub == 2) addr = r.un((int)elen - 1);
                    r.pos = next;
                } else switch (op) {
                    case 1: emit(false); break;
                    case 2: addr += r.uleb() * minInst; break;
                    case 3: ln += r.sleb(); break;
                    case 4: file = (int)r.uleb(); break;
                    case 5: r.uleb(); break;
                    case 6: stmt = !stmt; break;
                    case 7: break;
                    case 8: addr += (uint64_t)((255 - opBase) / lineRange) * minInst; break;
                    case 9: addr += r.u16(); break;
                    case 10: case 11: break;
                    case 12: r.uleb(); break;
                    default: for (int i = 0; i < stdLen[op - 1]; i++) r.uleb();
                }
            }
            r.pos = unitEnd;
        }
        std::stable_sort(rows.begin(), rows.end(), [](const LineRow &a, const LineRow &b) {
            if (a.addr != b.addr) return a.addr < b.addr;
            return a.end && !b.end;  // end_sequence of one CU before the start of the next
        });
    }

    const LineRow *find(uint64_t pc) const {
        auto it = std::upper_bound(rows.begin(), rows.end(), pc, [](uint64_t v, const LineRow &r) { return v < r.addr; });
        if (it == rows.begin()) return nullptr;
        --it;
        return it->end ? nullptr : &*it;
    }
};

// ---------------------------------------------------------------------------
// .debug_info  (functions, variables, types)
// ---------------------------------------------------------------------------
enum : uint16_t {
    TAG_array = 0x01, TAG_enum = 0x04, TAG_param = 0x05, TAG_block = 0x0b, TAG_member = 0x0d, TAG_pointer = 0x0f,
    TAG_cu = 0x11, TAG_struct = 0x13, TAG_typedef = 0x16, TAG_union = 0x17, TAG_subrange = 0x21, TAG_base = 0x24,
    TAG_const = 0x26, TAG_enumerator = 0x28, TAG_subprogram = 0x2e, TAG_variable = 0x34, TAG_volatile = 0x35
};
enum : uint16_t {
    AT_location = 0x02, AT_name = 0x03, AT_byte_size = 0x0b, AT_low_pc = 0x11, AT_high_pc = 0x12, AT_const_value = 0x1c,
    AT_upper_bound = 0x2f, AT_count = 0x37, AT_member_loc = 0x38, AT_frame_base = 0x40, AT_encoding = 0x3e,
    AT_type = 0x49, AT_ranges = 0x55
};

struct AttrVal { uint16_t form = 0; uint64_t u = 0; int64_t s = 0; std::string str; std::vector<uint8_t> blk; };
struct Die {
    uint64_t off; uint16_t tag; int parent;
    std::vector<int> kids;
    std::map<uint16_t, AttrVal> at;
    const AttrVal *get(uint16_t a) const { auto i = at.find(a); return i == at.end() ? nullptr : &i->second; }
    std::string name() const { auto *v = get(AT_name); return v ? v->str : std::string(); }
};
struct Func { std::string name; uint64_t lo, hi; int die; };
struct Abbrev { uint16_t tag; bool kids; std::vector<std::tuple<uint16_t, uint16_t, int64_t>> specs; };

struct DebugInfo {
    std::vector<Die> dies;
    std::map<uint64_t, int> byOff;
    std::vector<Func> funcs;
    std::vector<int> globals;
    Sec info, abbrev, str, lstr;
    std::map<uint64_t, std::map<uint64_t, Abbrev>> abbrCache;

    std::map<uint64_t, Abbrev> &abbrevAt(uint64_t off) {
        auto it = abbrCache.find(off);
        if (it != abbrCache.end()) return it->second;
        auto &tab = abbrCache[off];
        Reader r(abbrev.p, abbrev.n, off);
        for (;;) {
            uint64_t code = r.uleb();
            if (!code) break;
            Abbrev a;
            a.tag = (uint16_t)r.uleb();
            a.kids = r.u8();
            for (;;) {
                uint16_t n = (uint16_t)r.uleb(), f = (uint16_t)r.uleb();
                int64_t ic = 0;
                if (f == 0x21) ic = r.sleb();
                if (!n && !f) break;
                a.specs.push_back({n, f, ic});
            }
            tab[code] = a;
        }
        return tab;
    }

    AttrVal readForm(Reader &r, uint16_t form, int64_t ic, uint64_t cuOff, int addrSz, int offSz) {
        AttrVal v; v.form = form;
        auto blockN = [&](uint64_t n) { r.need(n); v.blk.assign(r.b + r.pos, r.b + r.pos + n); r.pos += n; };
        switch (form) {
            case 0x01: v.u = r.un(addrSz); break;
            case 0x03: blockN(r.u16()); break;
            case 0x04: blockN(r.u32()); break;
            case 0x05: v.u = r.u16(); break;
            case 0x06: v.u = r.u32(); break;
            case 0x07: v.u = r.u64(); break;
            case 0x08: v.str = r.cstr(); break;
            case 0x09: case 0x18: blockN(r.uleb()); break;
            case 0x0a: blockN(r.u8()); break;
            case 0x0b: v.u = r.u8(); break;
            case 0x0c: v.u = r.u8(); break;
            case 0x0d: v.s = r.sleb(); v.u = (uint64_t)v.s; break;
            case 0x0e: v.str = str.str(r.un(offSz)); break;
            case 0x0f: v.u = r.uleb(); break;
            case 0x10: v.u = r.un(offSz); break;
            case 0x11: v.u = cuOff + r.u8(); break;
            case 0x12: v.u = cuOff + r.u16(); break;
            case 0x13: v.u = cuOff + r.u32(); break;
            case 0x14: v.u = cuOff + r.u64(); break;
            case 0x15: v.u = cuOff + r.uleb(); break;
            case 0x16: return readForm(r, (uint16_t)r.uleb(), 0, cuOff, addrSz, offSz);
            case 0x17: v.u = r.un(offSz); break;
            case 0x19: v.u = 1; break;
            case 0x1a: case 0x1b: case 0x22: case 0x23: v.u = r.uleb(); break;
            case 0x1e: blockN(16); break;
            case 0x1f: v.str = lstr.str(r.un(offSz)); break;
            case 0x20: v.u = r.u64(); break;
            case 0x21: v.s = ic; v.u = (uint64_t)ic; break;
            case 0x25: case 0x29: v.u = r.u8(); break;
            case 0x26: case 0x2a: v.u = r.u16(); break;
            case 0x27: case 0x2b: v.u = r.un(3); break;
            case 0x28: case 0x2c: v.u = r.u32(); break;
            default: throw ElfError("unsupported DWARF form 0x" + std::to_string(form));
        }
        return v;
    }

    void parse() {
        Reader r(info.p, info.n);
        while (!r.eof()) {
            uint64_t cuOff = r.pos;
            uint64_t len = r.u32();
            int offSz = 4;
            if (len == 0xffffffff) { len = r.u64(); offSz = 8; }
            size_t end = r.pos + len;
            uint16_t ver = r.u16();
            uint64_t abbrOff; int addrSz;
            if (ver >= 5) {
                uint8_t ut = r.u8();
                addrSz = r.u8();
                abbrOff = r.un(offSz);
                if (ut == 4 || ut == 5) r.u64();
                if (ut == 2 || ut == 6) { r.u64(); r.un(offSz); }
            } else { abbrOff = r.un(offSz); addrSz = r.u8(); }
            auto &tab = abbrevAt(abbrOff);
            std::vector<int> stack;
            while (r.pos < end) {
                uint64_t doff = r.pos, code = r.uleb();
                if (!code) { if (!stack.empty()) stack.pop_back(); continue; }
                auto ai = tab.find(code);
                if (ai == tab.end()) throw ElfError("DWARF: bad abbreviation code");
                Die d; d.off = doff; d.tag = ai->second.tag; d.parent = stack.empty() ? -1 : stack.back();
                for (auto &sp : ai->second.specs)
                    d.at[std::get<0>(sp)] = readForm(r, std::get<1>(sp), std::get<2>(sp), cuOff, addrSz, offSz);
                int idx = (int)dies.size();
                byOff[doff] = idx;
                if (d.parent >= 0) dies[d.parent].kids.push_back(idx);
                bool kids = ai->second.kids;
                dies.push_back(std::move(d));
                if (kids) stack.push_back(idx);
            }
            r.pos = end;
        }
        for (size_t i = 0; i < dies.size(); i++) {
            Die &d = dies[i];
            if (d.tag == TAG_subprogram && d.get(AT_low_pc)) {
                uint64_t lo = d.get(AT_low_pc)->u, hi = lo;
                if (auto *h = d.get(AT_high_pc)) hi = (h->form == 0x01) ? h->u : lo + h->u;
                funcs.push_back({d.name(), lo, hi, (int)i});
            } else if (d.tag == TAG_variable && d.parent >= 0 && dies[d.parent].tag == TAG_cu && d.get(AT_location))
                globals.push_back((int)i);
        }
    }

    // ---- types ----
    int typeOf(int d) const {
        if (d < 0) return -1;
        auto *t = dies[d].get(AT_type);
        if (!t) return -1;
        auto it = byOff.find(t->u);
        return it == byOff.end() ? -1 : it->second;
    }
    int strip(int t) const {  // remove typedef / const / volatile
        while (t >= 0 && (dies[t].tag == TAG_typedef || dies[t].tag == TAG_const || dies[t].tag == TAG_volatile)) t = typeOf(t);
        return t;
    }
    uint64_t arrayCount(int a) const {
        for (int k : dies[a].kids)
            if (dies[k].tag == TAG_subrange) {
                if (auto *c = dies[k].get(AT_count)) return c->u;
                if (auto *u = dies[k].get(AT_upper_bound)) return u->u + 1;
            }
        return 0;
    }
    uint64_t sizeOf(int t) const {
        t = strip(t);
        if (t < 0) return 1;
        const Die &d = dies[t];
        if (auto *b = d.get(AT_byte_size)) return b->u;
        if (d.tag == TAG_pointer) return 8;
        if (d.tag == TAG_array) return sizeOf(typeOf(t)) * arrayCount(t);
        return 8;
    }
    std::string typeName(int t) const {
        if (t < 0) return "void";
        const Die &d = dies[t];
        switch (d.tag) {
            case TAG_pointer: return typeName(typeOf(t)) + "*";
            case TAG_const: return "const " + typeName(typeOf(t));
            case TAG_volatile: return "volatile " + typeName(typeOf(t));
            case TAG_struct: return "struct " + d.name();
            case TAG_union: return "union " + d.name();
            case TAG_enum: return "enum " + d.name();
            case TAG_array: return typeName(typeOf(t)) + "[" + std::to_string(arrayCount(t)) + "]";
            default: return d.name();
        }
    }
    int funcDieAt(uint64_t pc) const {
        for (auto &f : funcs) if (pc >= f.lo && pc < f.hi) return f.die;
        return -1;
    }
};

// ---------------------------------------------------------------------------
// The debugger
// ---------------------------------------------------------------------------
struct SymEnt { std::string name; uint64_t addr, size; uint8_t type; };
struct UserBp { int id; uint64_t addr; std::string desc; int hits = 0; bool enabled = true; };
enum Stop { S_EXIT, S_SIGNAL, S_BREAK, S_STEP, S_TEMP };

class Debugger {
public:
    Debugger(std::string exe, std::vector<std::string> args) : exePath(std::move(exe)), progArgs(std::move(args)) {}
    ~Debugger() { killInferior(); }
    void load();
    void repl();
    std::vector<std::string> searchDirs;

private:
    std::string exePath;
    std::vector<std::string> progArgs;
    ElfFile elf;
    LineTable lines;
    DebugInfo di;
    std::vector<SymEnt> syms;
    bool haveDwarf = false;

    pid_t pid = 0;
    bool alive = false;
    int pendingSig = 0;
    std::vector<UserBp> bps;
    int nextBp = 1, lastBpHit = 0;
    std::map<uint64_t, uint8_t> inserted;
    std::vector<uint64_t> temps;
    uint64_t lastFuncLo = ~0ull;
    std::string listFile;
    int listLine = 0, listNext = 0;
    std::map<std::string, std::vector<std::string>> srcCache;

    // --- process / memory ---
    void killInferior() {
        if (alive) { kill(pid, SIGKILL); int st; waitpid(pid, &st, 0); alive = false; }
        inserted.clear();
    }
    bool rawRead(uint64_t a, void *buf, size_t n) {
        uint8_t *o = (uint8_t *)buf;
        while (n) {
            errno = 0;
            long w = ptrace(PTRACE_PEEKDATA, pid, a & ~7ul, 0);
            if (errno) return false;
            size_t off = a & 7, c = std::min<size_t>(8 - off, n);
            memcpy(o, (uint8_t *)&w + off, c);
            o += c; a += c; n -= c;
        }
        return true;
    }
    bool rawWrite(uint64_t a, const void *buf, size_t n) {
        const uint8_t *s = (const uint8_t *)buf;
        while (n) {
            errno = 0;
            long w = ptrace(PTRACE_PEEKDATA, pid, a & ~7ul, 0);
            if (errno) return false;
            size_t off = a & 7, c = std::min<size_t>(8 - off, n);
            memcpy((uint8_t *)&w + off, s, c);
            if (ptrace(PTRACE_POKEDATA, pid, a & ~7ul, w) < 0) return false;
            s += c; a += c; n -= c;
        }
        return true;
    }
    bool readMem(uint64_t a, void *buf, size_t n) {  // like rawRead but hides our int3 bytes
        if (!alive || !rawRead(a, buf, n)) return false;
        for (auto &b : inserted) if (b.first >= a && b.first < a + n) ((uint8_t *)buf)[b.first - a] = b.second;
        return true;
    }
    uint64_t readU64(uint64_t a) { uint64_t v = 0; readMem(a, &v, 8); return v; }
    user_regs_struct regs() { user_regs_struct r{}; ptrace(PTRACE_GETREGS, pid, 0, &r); return r; }
    void setRegs(user_regs_struct &r) { ptrace(PTRACE_SETREGS, pid, 0, &r); }
    uint64_t pc() { return regs().rip; }

    void syncBps() {
        std::set<uint64_t> want(temps.begin(), temps.end());
        for (auto &b : bps) if (b.enabled) want.insert(b.addr);
        for (auto it = inserted.begin(); it != inserted.end();) {
            if (!want.count(it->first)) { rawWrite(it->first, &it->second, 1); it = inserted.erase(it); } else ++it;
        }
        for (uint64_t a : want) {
            if (inserted.count(a)) continue;
            uint8_t orig, cc = 0xCC;
            if (!rawRead(a, &orig, 1) || !rawWrite(a, &cc, 1)) { printf("warning: cannot insert breakpoint at 0x%lx\n", a); continue; }
            inserted[a] = orig;
        }
    }

    Stop waitStop() {
        int st;
        if (waitpid(pid, &st, 0) < 0) { alive = false; return S_EXIT; }
        if (WIFEXITED(st)) {
            alive = false; inserted.clear();
            if (WEXITSTATUS(st) == 0) printf("[Inferior exited normally]\n");
            else printf("[Inferior exited with code %d]\n", WEXITSTATUS(st));
            return S_EXIT;
        }
        if (WIFSIGNALED(st)) {
            alive = false; inserted.clear();
            printf("[Inferior terminated by signal %d (%s)]\n", WTERMSIG(st), strsignal(WTERMSIG(st)));
            return S_EXIT;
        }
        int sig = WSTOPSIG(st);
        if (sig == SIGTRAP) return S_STEP;
        pendingSig = sig;
        printf("\nProgram received signal %s (%s)\n", sigabbrev(sig), strsignal(sig));
        return S_SIGNAL;
    }
    static const char *sigabbrev(int s) {
        switch (s) { case SIGSEGV: return "SIGSEGV"; case SIGILL: return "SIGILL"; case SIGFPE: return "SIGFPE";
                     case SIGBUS: return "SIGBUS"; case SIGABRT: return "SIGABRT"; default: return "signal"; }
    }

    Stop singleStep() {
        uint64_t p = pc();
        auto it = inserted.find(p);
        if (it != inserted.end()) rawWrite(p, &it->second, 1);
        int sig = pendingSig; pendingSig = 0;
        fflush(stdout);
        ptrace(PTRACE_SINGLESTEP, pid, 0, sig);
        Stop s = waitStop();
        if (alive && it != inserted.end()) { uint8_t cc = 0xCC; rawWrite(p, &cc, 1); }
        return s;
    }

    // Resume until a breakpoint, a signal, exit, or (optionally) the temporary address `tmp`
    // is reached with rsp >= tmpSp (so recursion does not confuse "step over"/"finish").
    Stop cont(uint64_t tmp = 0, uint64_t tmpSp = 0) {
        temps.clear();
        if (tmp) temps.push_back(tmp);
        syncBps();
        auto done = [&](Stop s) { temps.clear(); if (alive) syncBps(); return s; };
        Stop s = singleStep();  // move off the current instruction (and any breakpoint on it)
        if (s != S_STEP) return done(s);
        for (;;) {
            user_regs_struct r = regs();
            if (tmp && r.rip == tmp && r.rsp >= tmpSp) return done(S_TEMP);
            fflush(stdout);
            ptrace(PTRACE_CONT, pid, 0, pendingSig);
            pendingSig = 0;
            s = waitStop();
            if (s != S_STEP) return done(s);
            r = regs();
            uint64_t a = r.rip - 1;
            if (!inserted.count(a)) return done(S_STEP);  // unexpected SIGTRAP
            r.rip = a;
            setRegs(r);
            bool user = false;
            for (auto &b : bps) if (b.enabled && b.addr == a) { b.hits++; if (!user) lastBpHit = b.id; user = true; }
            if (user) return done(S_BREAK);
            if (tmp && a == tmp && r.rsp >= tmpSp) return done(S_TEMP);
            s = singleStep();  // temp breakpoint in a deeper frame: keep going
            if (s != S_STEP) return done(s);
        }
    }

    bool isCall(uint64_t p) {
        uint8_t b[6] = {0};
        readMem(p, b, 6);
        size_t i = 0;
        while (i < 3 && (b[i] == 0x66 || b[i] == 0x67 || b[i] == 0xf2 || b[i] == 0x3e || (b[i] & 0xf0) == 0x40)) i++;
        return b[i] == 0xE8 || (b[i] == 0xFF && ((b[i + 1] >> 3) & 7) == 2);
    }

    // --- symbols / lines ---
    const Func *funcAt(uint64_t p) const {
        for (auto &f : di.funcs) if (p >= f.lo && p < f.hi) return &f;
        return nullptr;
    }
    bool inExecSection(uint64_t a) const {
        for (auto &sc : elf.sections)
            if ((sc.hdr.sh_flags & SHF_EXECINSTR) && a >= sc.hdr.sh_addr && a < sc.hdr.sh_addr + sc.hdr.sh_size) return true;
        return false;
    }
    std::string symbolize(uint64_t a, uint64_t *offset = nullptr) const {
        const SymEnt *best = nullptr;
        for (auto &s : syms)
            if (a >= s.addr && (a < s.addr + s.size || (s.size == 0 && a == s.addr)) && (!best || s.addr > best->addr)) best = &s;
        if (!best && inExecSection(a))
            for (auto &s : syms) if (s.type == STT_FUNC && s.addr <= a && (!best || s.addr > best->addr)) best = &s;
        if (!best) return "";
        if (offset) *offset = a - best->addr;
        return best->name;
    }
    std::string funcName(uint64_t a) const {
        if (auto *f = funcAt(a)) return f->name;
        return symbolize(a);
    }
    uint64_t afterPrologue(const Func &f) const {
        auto it = std::upper_bound(lines.rows.begin(), lines.rows.end(), f.lo, [](uint64_t v, const LineRow &r) { return v < r.addr; });
        for (; it != lines.rows.end() && it->addr < f.hi; ++it)
            if (!it->end && it->line) return it->addr;
        return f.lo;
    }
    static bool fileMatches(const std::string &path, const std::string &spec) {
        if (path == spec) return true;
        if (spec.find('/') == std::string::npos) return base_name(path) == spec;
        return path.size() >= spec.size() && path.compare(path.size() - spec.size(), spec.size(), spec) == 0;
    }

    // --- source files ---
    const std::vector<std::string> *source(const std::string &path) {
        auto it = srcCache.find(path);
        if (it != srcCache.end()) return it->second.empty() ? nullptr : &it->second;
        std::vector<std::string> cands = {path, base_name(path)};
        for (auto &d : searchDirs) cands.push_back(d + "/" + base_name(path));
        std::string exeDir = exePath.find('/') == std::string::npos ? "." : exePath.substr(0, exePath.rfind('/'));
        cands.push_back(exeDir + "/" + base_name(path));
        for (auto &c : cands) {
            std::ifstream f(c);
            if (!f) continue;
            std::vector<std::string> v; std::string l;
            while (std::getline(f, l)) v.push_back(l);
            if (v.empty()) v.push_back("");
            srcCache[path] = v;
            return &srcCache[path];
        }
        srcCache[path] = {};
        return nullptr;
    }
    void printSourceLine(const std::string &file, uint32_t line) {
        auto *s = source(file);
        if (s && line >= 1 && line <= s->size()) printf("%u\t%s\n", line, (*s)[line - 1].c_str());
        else printf("%u\tin %s (source file not found; use -d DIR)\n", line, file.c_str());
    }
    void showLocation(bool withFunc) {
        uint64_t p = pc();
        const LineRow *row = lines.find(p);
        const Func *f = funcAt(p);
        if (row && row->file >= 0) {
            const std::string &file = lines.files[row->file];
            if (withFunc || (f ? f->lo : 0) != lastFuncLo)
                printf("%s () at %s:%u\n", funcName(p).c_str(), base_name(file).c_str(), row->line);
            printSourceLine(file, row->line);
            listFile = file; listLine = row->line; listNext = 0;
        } else {
            uint64_t off = 0;
            std::string n = symbolize(p, &off);
            printf("0x%016lx in %s ()\n", p, n.empty() ? "??" : n.c_str());
        }
        lastFuncLo = f ? f->lo : 0;
    }
    void report(Stop s) {
        if (s == S_BREAK) {
            printf("\nBreakpoint %d, ", lastBpHit);
            showLocation(true);
        } else if (s == S_STEP || s == S_TEMP) showLocation(false);
        else if (s == S_SIGNAL) showLocation(true);
    }

    // --- breakpoints ---
    std::vector<uint64_t> addrsForLine(const std::string &file, int line, int &actual) {
        actual = 0;
        for (auto &r : lines.rows)
            if (!r.end && r.stmt && r.file >= 0 && r.line >= (uint32_t)line && fileMatches(lines.files[r.file], file))
                if (!actual || (int)r.line < actual) actual = r.line;
        std::map<uint64_t, uint64_t> perFunc;  // function start -> lowest address of that line
        if (actual)
            for (auto &r : lines.rows)
                if (!r.end && r.stmt && r.file >= 0 && (int)r.line == actual && fileMatches(lines.files[r.file], file)) {
                    const Func *f = funcAt(r.addr);
                    uint64_t key = f ? f->lo : r.addr;
                    if (!perFunc.count(key) || r.addr < perFunc[key]) perFunc[key] = r.addr;
                }
        std::vector<uint64_t> v;
        for (auto &kv : perFunc) v.push_back(kv.second);
        return v;
    }
    void cmdBreak(const std::string &spec) {
        std::vector<uint64_t> addrs;
        std::string desc;
        if (spec.empty()) { if (!alive) { puts("No default location."); return; } addrs.push_back(pc()); }
        else if (spec[0] == '*') addrs.push_back(strtoull(spec.c_str() + 1, nullptr, 0));
        else if (spec.find(':') != std::string::npos || isdigit((unsigned char)spec[0])) {
            std::string file = listFile;
            std::string ln = spec;
            size_t c = spec.rfind(':');
            if (c != std::string::npos) { file = spec.substr(0, c); ln = spec.substr(c + 1); }
            else if (file.empty()) { const Func *m = nullptr; for (auto &f : di.funcs) if (f.name == "main") m = &f;
                                     if (m) { const LineRow *r = lines.find(m->lo); if (r && r->file >= 0) file = lines.files[r->file]; } }
            int want = atoi(ln.c_str()), actual;
            addrs = addrsForLine(file, want, actual);
            if (addrs.empty()) { printf("No line %d in file \"%s\".\n", want, file.c_str()); return; }
            desc = base_name(file) + ":" + std::to_string(actual);
        } else {
            const Func *fn = nullptr;
            for (auto &f : di.funcs) if (f.name == spec) fn = &f;
            if (fn) { addrs.push_back(afterPrologue(*fn)); }
            else {
                for (auto &s : syms) if (s.type == STT_FUNC && s.name == spec) addrs.push_back(s.addr);
                if (addrs.empty()) { printf("Function \"%s\" not defined.\n", spec.c_str()); return; }
            }
        }
        for (uint64_t a : addrs) {
            UserBp b; b.id = nextBp++; b.addr = a;
            const LineRow *r = lines.find(a);
            if (r && r->file >= 0) b.desc = base_name(lines.files[r->file]) + ":" + std::to_string(r->line);
            else b.desc = desc;
            bps.push_back(b);
            printf("Breakpoint %d at 0x%lx: file %s\n", b.id, a, b.desc.empty() ? "?" : b.desc.c_str());
        }
        if (alive) syncBps();
    }

    // --- variables ---
    bool frameBase(int fd, uint64_t &fb) {
        auto *v = di.dies[fd].get(AT_frame_base);
        user_regs_struct r = regs();
        if (!v || v->blk.empty()) return false;
        uint8_t op = v->blk[0];
        if (op == 0x9c) { fb = r.rbp + 16; return true; }   // DW_OP_call_frame_cfa (valid after the prologue)
        if (op == 0x56) { fb = r.rbp; return true; }        // DW_OP_reg6 (rbp)
        if (op == 0x76) { Reader rd(v->blk.data(), v->blk.size(), 1); fb = r.rbp + rd.sleb(); return true; }
        return false;
    }
    bool varAddress(int vd, int fd, uint64_t &addr, std::string &why) {
        auto *loc = di.dies[vd].get(AT_location);
        if (!loc || loc->blk.empty()) { why = "<optimized out or location list>"; return false; }
        uint8_t op = loc->blk[0];
        if (op == 0x03 && loc->blk.size() >= 9) { memcpy(&addr, &loc->blk[1], 8); return true; }
        if (op == 0x91 && fd >= 0) {
            Reader rd(loc->blk.data(), loc->blk.size(), 1);
            int64_t off = rd.sleb();
            uint64_t fb;
            if (!frameBase(fd, fb)) { why = "<unsupported frame base>"; return false; }
            addr = fb + off;
            return true;
        }
        why = "<unsupported location expression>";
        return false;
    }
    void collectVars(int scope, uint64_t p, std::vector<int> &out) {
        for (int k : di.dies[scope].kids) {
            const Die &d = di.dies[k];
            if (d.tag == TAG_variable || d.tag == TAG_param) out.push_back(k);
            else if (d.tag == TAG_block) {
                bool in = true;
                if (d.get(AT_low_pc) && d.get(AT_high_pc)) {
                    uint64_t lo = d.get(AT_low_pc)->u, hi = d.get(AT_high_pc)->form == 0x01 ? d.get(AT_high_pc)->u : lo + d.get(AT_high_pc)->u;
                    in = p >= lo && p < hi;
                }
                if (in) collectVars(k, p, out);
            }
        }
    }
    int findVar(const std::string &name, int &fd) {
        fd = alive ? di.funcDieAt(pc()) : -1;
        if (fd >= 0) {
            std::vector<int> v;
            collectVars(fd, pc(), v);
            for (auto it = v.rbegin(); it != v.rend(); ++it) if (di.dies[*it].name() == name) return *it;
        }
        for (int g : di.globals) if (di.dies[g].name() == name) return g;
        return -1;
    }

    static std::string escape(const std::string &in) {
        std::string o;
        for (char c : in) {
            if (c == '\n') o += "\\n"; else if (c == '\t') o += "\\t"; else if (c == '"') o += "\\\""; else o += c;
        }
        return o;
    }
    std::string fmtValue(int t, const std::vector<uint8_t> &buf, size_t off, bool hex, int depth = 0) {
        int s = di.strip(t);
        if (s < 0) return "void";
        const Die &d = di.dies[s];
        uint64_t size = di.sizeOf(s);
        if (off + size > buf.size() || depth > 4) return "<?>";
        auto raw = [&](uint64_t n) { uint64_t v = 0; memcpy(&v, buf.data() + off, std::min<uint64_t>(n, 8)); return v; };
        char tmp[64];
        switch (d.tag) {
            case TAG_base: {
                int enc = d.get(AT_encoding) ? (int)d.get(AT_encoding)->u : 5;
                uint64_t u = raw(size);
                if (enc == 4) {
                    if (size == 4) { float f; memcpy(&f, &u, 4); snprintf(tmp, sizeof tmp, "%g", f); return tmp; }
                    if (size == 8) { double f; memcpy(&f, &u, 8); snprintf(tmp, sizeof tmp, "%g", f); return tmp; }
                    return "<float>";
                }
                if (enc == 2) return u ? "true" : "false";
                bool sgn = (enc == 5 || enc == 6 || enc == 0x0d);
                if (hex) { snprintf(tmp, sizeof tmp, "0x%lx", u); return tmp; }
                if (sgn && size < 8) { int sh = 64 - 8 * (int)size; int64_t v = (int64_t)(u << sh) >> sh; snprintf(tmp, sizeof tmp, "%ld", v); }
                else if (sgn) snprintf(tmp, sizeof tmp, "%ld", (int64_t)u);
                else snprintf(tmp, sizeof tmp, "%lu", u);
                std::string r = tmp;
                if ((enc == 6 || enc == 8) && size == 1 && u >= 32 && u < 127) r += std::string(" '") + (char)u + "'";
                return r;
            }
            case TAG_pointer: {
                uint64_t u = raw(8);
                snprintf(tmp, sizeof tmp, "(%s) 0x%lx", di.typeName(t).c_str(), u);
                std::string r = tmp;
                if (u && inExecSection(u) && !symbolize(u).empty()) r += " <" + symbolize(u) + ">";
                int pt = di.strip(di.typeOf(s));
                if (u && pt >= 0 && di.dies[pt].tag == TAG_base && di.sizeOf(pt) == 1) {
                    std::string str; char c;
                    for (int i = 0; i < 60 && readMem(u + i, &c, 1) && c; i++) str += c;
                    r += " \"" + escape(str) + "\"";
                }
                return r;
            }
            case TAG_enum: {
                uint64_t u = raw(size);
                for (int k : d.kids) if (di.dies[k].tag == TAG_enumerator && di.dies[k].get(AT_const_value) && di.dies[k].get(AT_const_value)->u == u) return di.dies[k].name();
                snprintf(tmp, sizeof tmp, "%lu", u);
                return tmp;
            }
            case TAG_struct: case TAG_union: {
                std::string r = "{";
                bool first = true;
                for (int k : d.kids) {
                    if (di.dies[k].tag != TAG_member) continue;
                    uint64_t mo = di.dies[k].get(AT_member_loc) ? di.dies[k].get(AT_member_loc)->u : 0;
                    if (!first) r += ", ";
                    first = false;
                    r += di.dies[k].name() + " = " + fmtValue(di.typeOf(k), buf, off + mo, hex, depth + 1);
                }
                return r + "}";
            }
            case TAG_array: {
                int et = di.typeOf(s);
                uint64_t es = di.sizeOf(et), n = di.arrayCount(s);
                int ets = di.strip(et);
                if (ets >= 0 && di.dies[ets].tag == TAG_base && es == 1 && di.dies[ets].get(AT_encoding) &&
                    (di.dies[ets].get(AT_encoding)->u == 6 || di.dies[ets].get(AT_encoding)->u == 8)) {
                    std::string str;
                    for (uint64_t i = 0; i < n && buf[off + i]; i++) str += (char)buf[off + i];
                    return "\"" + escape(str) + "\"";
                }
                std::string r = "{";
                for (uint64_t i = 0; i < n && i < 16; i++) { if (i) r += ", "; r += fmtValue(et, buf, off + i * es, hex, depth + 1); }
                if (n > 16) r += ", ...";
                return r + "}";
            }
            default: return "<unsupported type>";
        }
    }
    void printVar(int vd, int fd, bool hex, bool withName = true) {
        std::string name = di.dies[vd].name(), why;
        uint64_t addr;
        if (!varAddress(vd, fd, addr, why)) { printf("%s = %s\n", name.c_str(), why.c_str()); return; }
        int t = di.typeOf(vd);
        uint64_t sz = std::min<uint64_t>(di.sizeOf(t), 4096);
        std::vector<uint8_t> buf(sz);
        if (!readMem(addr, buf.data(), sz)) { printf("%s = <cannot read memory at 0x%lx>\n", name.c_str(), addr); return; }
        std::string v = fmtValue(t, buf, 0, hex);
        if (withName) printf("%s = %s\n", name.c_str(), v.c_str()); else printf("%s\n", v.c_str());
    }

    struct RegEnt { const char *name; unsigned long long user_regs_struct::*p; };
    static const std::vector<RegEnt> &regTable() {
        static const std::vector<RegEnt> t = {
            {"rax", &user_regs_struct::rax}, {"rbx", &user_regs_struct::rbx}, {"rcx", &user_regs_struct::rcx},
            {"rdx", &user_regs_struct::rdx}, {"rsi", &user_regs_struct::rsi}, {"rdi", &user_regs_struct::rdi},
            {"rbp", &user_regs_struct::rbp}, {"rsp", &user_regs_struct::rsp}, {"r8", &user_regs_struct::r8},
            {"r9", &user_regs_struct::r9}, {"r10", &user_regs_struct::r10}, {"r11", &user_regs_struct::r11},
            {"r12", &user_regs_struct::r12}, {"r13", &user_regs_struct::r13}, {"r14", &user_regs_struct::r14},
            {"r15", &user_regs_struct::r15}, {"rip", &user_regs_struct::rip}, {"eflags", &user_regs_struct::eflags},
            {"cs", &user_regs_struct::cs}, {"ss", &user_regs_struct::ss}, {"ds", &user_regs_struct::ds},
            {"es", &user_regs_struct::es}, {"fs", &user_regs_struct::fs}, {"gs", &user_regs_struct::gs},
            {"fs_base", &user_regs_struct::fs_base}, {"gs_base", &user_regs_struct::gs_base}};
        return t;
    }

    bool needProcess() { if (!alive) { puts("The program is not being run."); return false; } return true; }
    bool evalNumber(const std::string &e, uint64_t &out) {  // number, $reg, &var, or variable value
        if (e.empty()) return false;
        if (e[0] == '$') {
            user_regs_struct r = regs();
            for (auto &re : regTable()) if (e.substr(1) == re.name) { out = r.*(re.p); return true; }
            return false;
        }
        if (isdigit((unsigned char)e[0])) { out = strtoull(e.c_str(), nullptr, 0); return true; }
        bool addrOf = e[0] == '&';
        int fd, v = findVar(addrOf ? e.substr(1) : e, fd);
        if (v < 0) return false;
        std::string why; uint64_t a;
        if (!varAddress(v, fd, a, why)) return false;
        if (addrOf) { out = a; return true; }
        out = 0;
        return readMem(a, &out, std::min<uint64_t>(di.sizeOf(di.typeOf(v)), 8));
    }

    // --- commands ---
    void cmdPrint(const std::string &fmtSpec, const std::string &expr) {
        bool hex = fmtSpec.find('x') != std::string::npos;
        if (expr.empty()) { puts("Argument required (an expression to compute)."); return; }
        if (!needProcess()) return;
        if (expr[0] == '&') {
            int fd, v = findVar(expr.substr(1), fd);
            std::string why; uint64_t a;
            if (v < 0 || !varAddress(v, fd, a, why)) { printf("No symbol \"%s\" in current context.\n", expr.substr(1).c_str()); return; }
            std::string sym = symbolize(a);
            printf("(%s*) 0x%lx%s\n", di.typeName(di.typeOf(v)).c_str(), a, sym.empty() ? "" : (" <" + sym + ">").c_str());
            return;
        }
        if (expr[0] == '$' || isdigit((unsigned char)expr[0])) {
            uint64_t v;
            if (!evalNumber(expr, v)) { printf("Cannot evaluate '%s'.\n", expr.c_str()); return; }
            if (hex || expr[0] == '$') printf("%s = 0x%lx (%ld)\n", expr.c_str(), v, (int64_t)v);
            else printf("%lu\n", v);
            return;
        }
        int fd, v = findVar(expr, fd);
        if (v < 0) { printf("No symbol \"%s\" in current context.\n", expr.c_str()); return; }
        printVar(v, fd, hex, false);
    }
    void cmdLocals(bool params) {
        if (!needProcess()) return;
        int fd = di.funcDieAt(pc());
        if (fd < 0) { puts("No symbol table info available."); return; }
        std::vector<int> v;
        collectVars(fd, pc(), v);
        bool any = false;
        for (int k : v)
            if ((di.dies[k].tag == TAG_param) == params) { printVar(k, fd, false); any = true; }
        if (!any) puts(params ? "No arguments." : "No locals.");
    }
    void cmdSetVar(const std::string &rest) {
        size_t eq = rest.find('=');
        if (eq == std::string::npos) { puts("usage: set var NAME = VALUE"); return; }
        auto trim = [](std::string s) { size_t a = s.find_first_not_of(" \t"), b = s.find_last_not_of(" \t"); return a == std::string::npos ? std::string() : s.substr(a, b - a + 1); };
        std::string name = trim(rest.substr(0, eq)), val = trim(rest.substr(eq + 1));
        if (!needProcess()) return;
        int fd, v = findVar(name, fd);
        if (v < 0) { printf("No symbol \"%s\" in current context.\n", name.c_str()); return; }
        std::string why; uint64_t a;
        if (!varAddress(v, fd, a, why)) { puts(why.c_str()); return; }
        uint64_t sz = di.sizeOf(di.typeOf(v));
        if (sz > 8) { puts("Only scalar variables can be assigned."); return; }
        int64_t x = strtoll(val.c_str(), nullptr, 0);
        if (!rawWrite(a, &x, sz)) puts("Cannot write memory.");
    }
    void cmdBacktrace() {
        if (!needProcess()) return;
        user_regs_struct r = regs();
        uint64_t p = r.rip, fp = r.rbp;
        for (int i = 0; i < 32; i++) {
            const LineRow *row = lines.find(i == 0 ? p : p - 1);
            std::string n = funcName(i == 0 ? p : p - 1);
            printf("#%-2d ", i);
            if (i) printf("0x%016lx in ", p);
            printf("%s ()", n.empty() ? "??" : n.c_str());
            if (row && row->file >= 0) printf(" at %s:%u", base_name(lines.files[row->file]).c_str(), row->line);
            puts("");
            if (!fp || n == "main") break;
            uint64_t ret = readU64(fp + 8), next = readU64(fp);
            if (!ret) break;
            p = ret; fp = next;
        }
    }
    void cmdRegs() {
        if (!needProcess()) return;
        user_regs_struct r = regs();
        for (auto &re : regTable()) {
            unsigned long long v = r.*(re.p);
            printf("%-8s 0x%-16llx %lld\n", re.name, v, (long long)v);
        }
    }
    void cmdExamine(const std::string &fmtSpec, const std::string &expr) {
        if (!needProcess()) return;
        int count = 1; char f = 'x';
        for (size_t i = 0; i < fmtSpec.size(); i++) {
            if (isdigit((unsigned char)fmtSpec[i])) { count = atoi(fmtSpec.c_str() + i); while (i + 1 < fmtSpec.size() && isdigit((unsigned char)fmtSpec[i + 1])) i++; }
            else f = fmtSpec[i];
        }
        uint64_t a;
        if (!evalNumber(expr, a)) { printf("Cannot evaluate '%s'.\n", expr.c_str()); return; }
        if (f == 's') {
            for (int i = 0; i < count; i++) {
                std::string s; char c;
                uint64_t start = a;
                while (readMem(a, &c, 1) && c) { s += c; a++; }
                a++;
                printf("0x%lx:\t\"%s\"\n", start, escape(s).c_str());
            }
            return;
        }
        for (int i = 0; i < count; i++, a += 8) {
            uint64_t v;
            if (!readMem(a, &v, 8)) { printf("Cannot access memory at 0x%lx\n", a); return; }
            uint64_t off = 0;
            std::string sym = symbolize(a, &off);
            printf("0x%lx", a);
            if (!sym.empty()) printf(" <%s+%lu>", sym.c_str(), off);
            printf(":\t0x%016lx\n", v);
        }
    }
    void cmdList(const std::string &arg) {
        std::string file = listFile;
        int center = 0;
        if (!arg.empty()) {
            size_t c = arg.rfind(':');
            if (c != std::string::npos) { file = arg.substr(0, c); center = atoi(arg.c_str() + c + 1); }
            else if (isdigit((unsigned char)arg[0])) center = atoi(arg.c_str());
            else for (auto &f : di.funcs) if (f.name == arg) { const LineRow *r = lines.find(f.lo); if (r && r->file >= 0) { file = lines.files[r->file]; center = r->line; } }
            for (auto &lf : lines.files) if (fileMatches(lf, file)) { file = lf; break; }
        } else if (listNext) center = listNext + 5;
        else center = listLine ? listLine : 1;
        if (file.empty()) {
            for (auto &f : di.funcs) if (f.name == "main") { const LineRow *r = lines.find(f.lo); if (r && r->file >= 0) { file = lines.files[r->file]; center = r->line; } }
        }
        auto *s = source(file);
        if (!s) { printf("Cannot open source file '%s'.\n", file.c_str()); return; }
        int start = std::max(1, center - 5), end = std::min<int>((int)s->size(), start + 9);
        for (int i = start; i <= end; i++) printf("%d\t%s\n", i, (*s)[i - 1].c_str());
        listFile = file; listNext = end;
    }
    void cmdInfoBreak() {
        if (bps.empty()) { puts("No breakpoints or watchpoints."); return; }
        puts("Num  Enb  Address            Hits  What");
        for (auto &b : bps) printf("%-4d %-4s 0x%016lx %-5d %s\n", b.id, b.enabled ? "y" : "n", b.addr, b.hits, b.desc.c_str());
    }
    void cmdDumpLines() {  // like `objdump --dwarf=decodedline`
        printf("%-18s %-6s %-5s %s\n", "ADDRESS", "LINE", "STMT", "FILE");
        for (auto &r : lines.rows)
            printf("0x%016lx %-6s %-5s %s\n", r.addr, r.end ? "-" : std::to_string(r.line).c_str(), r.stmt ? "x" : "",
                   r.file >= 0 ? base_name(lines.files[r.file]).c_str() : "?");
    }
    void run() {
        killInferior();
        fflush(stdout);
        pid = fork();
        if (pid == 0) {
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            personality(ADDR_NO_RANDOMIZE);
            std::vector<char *> av;
            av.push_back((char *)exePath.c_str());
            for (auto &a : progArgs) av.push_back((char *)a.c_str());
            av.push_back(nullptr);
            execv(exePath.c_str(), av.data());
            perror("execv");
            _exit(127);
        }
        int st;
        waitpid(pid, &st, 0);
        if (!WIFSTOPPED(st)) { puts("Failed to start program."); return; }
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
        alive = true; pendingSig = 0; lastFuncLo = ~0ull;
        for (auto &b : bps) b.hits = 0;
        report(cont());
    }
    bool landedOnBreakpoint() {  // stepping reached an enabled breakpoint: report it like gdb does
        uint64_t p = pc();
        bool hit = false;
        for (auto &b : bps) if (b.enabled && b.addr == p) { b.hits++; if (!hit) lastBpHit = b.id; hit = true; }
        return hit;
    }
    void doStep(bool over) {
        if (!needProcess()) return;
        const LineRow *row = lines.find(pc());
        if (!row) { report(cont()); return; }  // no line info here: just run on
        uint32_t startLine = row->line;
        const Func *startFn = funcAt(pc());
        for (;;) {
            bool call = isCall(pc());
            uint64_t spBefore = regs().rsp;
            Stop s = singleStep();
            if (s != S_STEP) { report(s); return; }
            if (landedOnBreakpoint()) { report(S_BREAK); return; }
            if (call) {
                uint64_t p = pc();
                const Func *f = funcAt(p);
                if (over || !f || !lines.find(p)) {
                    s = cont(readU64(regs().rsp), spBefore);
                    if (s != S_TEMP) { report(s); return; }
                } else {
                    uint64_t ap = afterPrologue(*f);
                    if (ap != p) { s = cont(ap, 0); if (s != S_TEMP) { report(s); return; } }
                    report(S_STEP);
                    return;
                }
            }
            uint64_t p = pc();
            row = lines.find(p);
            if (!row || row->addr != p || !row->stmt || !row->line) continue;
            if (row->line != startLine || funcAt(p) != startFn) { report(S_STEP); return; }
        }
    }

public:
    void execute(const std::string &line);
};

void Debugger::load() {
    elf.load(exePath, read_whole_file(exePath));
    if (elf.eh.e_type != ET_EXEC)
        throw ElfError(exePath + ": only fixed-address executables (ET_EXEC) are supported; "
                                 "PIE binaries need a load bias. Link with mylink or use gcc -no-pie -static");
    for (size_t i = 0; i < elf.sections.size(); i++) {
        const Elf64_Shdr &h = elf.sections[i].hdr;
        if (h.sh_type != SHT_SYMTAB) continue;
        const Elf64_Sym *s = (const Elf64_Sym *)elf.data(i);
        for (size_t k = 1; k < h.sh_size / sizeof(Elf64_Sym); k++) {
            uint8_t t = ELF64_ST_TYPE(s[k].st_info);
            if ((t == STT_FUNC || t == STT_OBJECT || t == STT_NOTYPE) && s[k].st_shndx != SHN_UNDEF && s[k].st_shndx < SHN_LORESERVE)
                if (const char *n = elf.sym_name(h, s[k].st_name); *n && n[0] != '.')
                    syms.push_back({n, s[k].st_value, s[k].st_size, t});
        }
    }
    auto sec = [&](const char *n) { Sec r; int i = elf.find(n); if (i >= 0 && elf.data(i)) { r.p = elf.data(i); r.n = elf.sections[i].hdr.sh_size; } return r; };
    Sec dl = sec(".debug_line");
    di.info = sec(".debug_info"); di.abbrev = sec(".debug_abbrev"); di.str = sec(".debug_str"); di.lstr = sec(".debug_line_str");
    if (dl.p) lines.parse(dl, di.str, di.lstr);
    if (di.info.p && di.abbrev.p) di.parse();
    haveDwarf = dl.p != nullptr;
    printf("Reading symbols from %s... (%zu functions, %zu line-table rows%s)\n", exePath.c_str(), di.funcs.size(),
           lines.rows.size(), haveDwarf ? "" : "; NO DEBUG INFO - compile with -g");
}

void Debugger::execute(const std::string &raw) {
    std::istringstream is(raw);
    std::string cmd, rest;
    is >> cmd;
    std::getline(is, rest);
    size_t a = rest.find_first_not_of(" \t");
    rest = a == std::string::npos ? "" : rest.substr(a);
    while (!rest.empty() && isspace((unsigned char)rest.back())) rest.pop_back();
    std::string fmtSpec;
    size_t sl = cmd.find('/');
    if (sl != std::string::npos) { fmtSpec = cmd.substr(sl + 1); cmd = cmd.substr(0, sl); }

    if (cmd.empty()) return;
    if (cmd == "break" || cmd == "b" || cmd == "br") cmdBreak(rest);
    else if (cmd == "run" || cmd == "r") run();
    else if (cmd == "continue" || cmd == "c") { if (needProcess()) report(cont()); }
    else if (cmd == "next" || cmd == "n") doStep(true);
    else if (cmd == "step" || cmd == "s") doStep(false);
    else if (cmd == "stepi" || cmd == "si") {
        if (!needProcess()) return;
        Stop s = singleStep();
        if (s == S_STEP) {
            uint64_t p = pc();
            const LineRow *r = lines.find(p);
            if (r && r->file >= 0) printf("0x%016lx\t%s:%u\n", p, base_name(lines.files[r->file]).c_str(), r->line);
            else printf("0x%016lx in %s ()\n", p, funcName(p).c_str());
        } else report(s);
    }
    else if (cmd == "finish") {
        if (!needProcess()) return;
        user_regs_struct r = regs();
        const Func *f = funcAt(r.rip);
        if (f && r.rip == f->lo) { puts("Stopped at function entry; use 'next' first."); return; }
        printf("Run till exit from %s ()\n", funcName(r.rip).c_str());
        report(cont(readU64(r.rbp + 8), r.rbp + 16));
    }
    else if (cmd == "print" || cmd == "p" || cmd == "inspect") cmdPrint(fmtSpec, rest);
    else if (cmd == "x") cmdExamine(fmtSpec, rest);
    else if (cmd == "locals") cmdLocals(false);
    else if (cmd == "args") cmdLocals(true);
    else if (cmd == "regs" || cmd == "registers") cmdRegs();
    else if (cmd == "bt" || cmd == "backtrace" || cmd == "where") cmdBacktrace();
    else if (cmd == "list" || cmd == "l") cmdList(rest);
    else if (cmd == "lines") cmdDumpLines();
    else if (cmd == "set") { if (rest.compare(0, 4, "var ") == 0) cmdSetVar(rest.substr(4)); else cmdSetVar(rest); }
    else if (cmd == "directory" || cmd == "dir") { searchDirs.push_back(rest); srcCache.clear(); }
    else if (cmd == "delete" || cmd == "d") {
        if (rest.empty()) bps.clear();
        else { int id = atoi(rest.c_str()); bps.erase(std::remove_if(bps.begin(), bps.end(), [&](const UserBp &b) { return b.id == id; }), bps.end()); }
        if (alive) syncBps();
    }
    else if (cmd == "disable" || cmd == "enable") {
        for (auto &b : bps) if (rest.empty() || b.id == atoi(rest.c_str())) b.enabled = (cmd == "enable");
        if (alive) syncBps();
    }
    else if (cmd == "info" || cmd == "i") {
        if (rest == "breakpoints" || rest == "break" || rest == "b") cmdInfoBreak();
        else if (rest == "registers" || rest == "reg" || rest == "r") cmdRegs();
        else if (rest == "locals") cmdLocals(false);
        else if (rest == "args") cmdLocals(true);
        else if (rest == "line" || rest == "lines") cmdDumpLines();
        else if (rest == "functions") for (auto &f : di.funcs) printf("0x%016lx  %s\n", f.lo, f.name.c_str());
        else puts("info: breakpoints | registers | locals | args | lines | functions");
    }
    else if (cmd == "help" || cmd == "h" || cmd == "?")
        puts("break|b FILE:LINE | LINE | FUNC | *ADDR   set breakpoint\n"
             "run|r   continue|c   next|n   step|s   stepi|si   finish\n"
             "print|p[/x] VAR|$REG|&VAR   locals   args   set var NAME = VALUE\n"
             "x[/Nx|/Ns] ADDR   bt   regs   list|l [N|FILE:N|FUNC]\n"
             "info breakpoints|functions|lines   delete [N]   enable|disable [N]   lines   quit|q");
    else if (cmd == "quit" || cmd == "q" || cmd == "exit") { killInferior(); exit(0); }
    else printf("Undefined command: \"%s\".  Try \"help\".\n", cmd.c_str());
}

void Debugger::repl() {
    std::string line;
    bool tty = isatty(0);
    for (;;) {
        if (tty) { printf("(mydbg) "); fflush(stdout); }
        if (!std::getline(std::cin, line)) break;
        if (!tty) { printf("(mydbg) %s\n", line.c_str()); fflush(stdout); }
        try { execute(line); } catch (const std::exception &e) { printf("error: %s\n", e.what()); }
        fflush(stdout);
    }
    if (alive) printf("\n");
}

}  // namespace

int main(int argc, char **argv) {
    std::vector<std::string> dirs;
    int i = 1;
    for (; i < argc && argv[i][0] == '-'; i++) {
        std::string a = argv[i];
        if (a == "-d" && i + 1 < argc) dirs.push_back(argv[++i]);
        else if (a == "--") { i++; break; }
        else { fprintf(stderr, "usage: mydbg [-d SRCDIR] program [args...]\n"); return 1; }
    }
    if (i >= argc) { fprintf(stderr, "usage: mydbg [-d SRCDIR] program [args...]\n"); return 1; }
    std::string exe = argv[i++];
    if (exe.find('/') == std::string::npos) exe = "./" + exe;
    std::vector<std::string> args(argv + i, argv + argc);
    try {
        Debugger d(exe, args);
        d.searchDirs = dirs;
        d.load();
        d.repl();
    } catch (const std::exception &e) {
        fprintf(stderr, "mydbg: %s\n", e.what());
        return 1;
    }
    return 0;
}
