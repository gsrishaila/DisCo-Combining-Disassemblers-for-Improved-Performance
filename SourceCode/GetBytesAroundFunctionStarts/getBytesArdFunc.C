/*
 * elfmap.C
 *
 * Dennis Andriesse <da.andriesse@few.vu.nl>
 * VU University Amsterdam
 * August 2015
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <assert.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <getopt.h>
#define HAVE_DECL_BASENAME 1 /* fix nameclash for basename in libiberty */
#include <libiberty/demangle.h>

#include <execinfo.h>

#include <gelf.h>
#include <libelf.h>

#ifndef EM_X86_64
#define EM_X86_64  EM_AMD64
#endif /* EM_X86_64 */

#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>
#include <capstone/capstone.h>

#include <string>
#include <sstream>
#include <algorithm>
#include <vector>
#include <set>
#include <map>
#include <deque>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <boost/algorithm/string.hpp>


#define ELFMAP_VERSION  "elfmap v0.71"
#define ELFMAP_CREDITS  "Copyright (C) 2015 Dennis Andriesse\n"                                       \
                        "This is free software; see the source for copying conditions. There is NO\n" \
                        "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."

#define DWARF_MIN_VERSION                 2
#define DWARF_FUNC_SIG_MIN_VERSION        3
#define DWARF_MAX_VERSION                 4
#define DWARF_MIN_VERSION_STRING          "dwarf v2"
#define DWARF_FUNC_SIG_MIN_VERSION_STRING "dwarf v3"
#define DWARF_MAX_VERSION_STRING          "dwarf v4"
#define DWARF_DIENAME_NONE                "(unnamed)"

#define DUMP_PARTIAL_FUNCS  1  /* set to non-zero to dump functions without signature info */

#define X86_MAX_INS_LEN  16
#define CODE_CHUNK_SIZE  4096  /* 4K ought to be enough for anybody */

#define ERROUT  stdout

/* text colors */
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

int verbosity = 0;
int warnings  = 1;

int have_llvminfo            = 0;
int skip_func_sigs           = 0;
int track_overlapping_blocks = 0;
int track_funcs              = 0;
int guess_func_entry         = 0;
int guess_return             = 0;
int ignore_fallthrough       = 0;
int ignore_padding           = 0;
int symbols_only             = 0;
int allow_overlapping_ins    = 0;
int map_show_insbounds       = 0;
int map_limit_16_bytes       = 0;


void __bt_assert(bool c);
#define bt_assert(c) assert(c)
void verbose(int level, char const *fmt, ...);

//shaila
std::set<uint64_t> printInstSet;
std::set<uint64_t> DataAddInCodeSeg;
std::set<uint64_t> BBStartAdd;
std::set<uint64_t> globalTargets;   //get the jump targets to a particular inst in a func
std::set<uint64_t> globalFuncStarts;
std::vector<uint64_t> globalFuncStartsVect; 
std::map<int, int> cmpRegMapForArm; //for arm to detect the jump table data included in the code section
//mips switch
std::map<int, int> luiRegMapForMIPS;
std::map<int, int> addiuRegMapForMIPS;
//Key:1 Val:address of latest sltiu inst 
//Key:2 Val:address of latest beqz inst 
//Key:3 Val:address of latest sll inst 
//Key:4 Val:address of latest lw inst
//Key:5 Val:address of latest jr inst
std::map<int, int> mipsSwitchJumpsAfterThisBlk;
int roDataToReadSwitchCases=-1;
int jmpsAfterroDataToReadSwitchCases=0;
std::set<uint64_t> switchCasesSllTargets;
std::map<std::string,int>sectionStartsAdd;
std::map<std::string,int>sectionEndsAdd;
std::map<std::string,int>sectionSize;
//mips switch
std::map<uint64_t, uint64_t> instBytesMap; //for arm to contains the bytes for each instr so that we know the add pointed to by jump tables in code
std::set<uint64_t> jmpTableAddresses;
uint64_t nexInstAddrToCont=0;
uint64_t sltiuSwitchCaseNo=-1;

//func start add set#this is to get the bytes ard func start
std::set<uint64_t> funcStartAddSet;
char *funcBytesInfoTxt;
std::map<int,char*>mlAddDetails;


struct balInfo{ //for mips
  uint64_t    balAddLoc ;         
  uint64_t    balAddTarget;
  bool operator <(const balInfo& bI) const
  {  
	return (balAddLoc<bI.balAddLoc) || ((!(bI.balAddLoc<balAddLoc)) && (balAddTarget<bI.balAddTarget));
  }       
};
std::set<balInfo> balTargets;

struct bInfo{ //for arm - find the Branch (B) that call(Jump) to start of a function
  uint64_t    bAddLoc ;         
  uint64_t    bAddTarget;
  bool operator <(const bInfo& bIn) const
  {  
	return (bAddLoc<bIn.bAddLoc) || ((!(bIn.bAddLoc<bAddLoc)) && (bAddTarget<bIn.bAddTarget));
  }       
};
std::set<bInfo> bTargets;

struct callInfo{ //for arm - find the Branch (B) that call(Jump) to start of a function
  uint64_t    callAddLoc ;         
  uint64_t    callAddTarget;
  bool operator <(const callInfo& callIn) const
  {  
	return (callAddLoc<callIn.callAddLoc) || ((!(callIn.callAddLoc<callAddLoc)) && (callAddTarget<callIn.callAddTarget));
  }       
};
std::set<callInfo> callTargets;


struct InstrInfo{ //for arm - find the Branch (B) that call(Jump) to start of a function        
  //char        *opcode;
  //char	      *operands;
  char        opcode[32];
  char        operands[160];
  int	      isCond;
  std::set<uint64_t> targetSet;     
};
std::set<InstrInfo> InstrInfoStruct;
std::map<uint64_t, InstrInfo> InstrInfoMaps;

//shaila
typedef struct {
  int         fd;            /* file descriptor     */
  Elf        *e;             /* main ELF descriptor */
  int         bits;          /* 32-bit or 64-bit    */
  uint64_t    entry;         /* ELF entry point     */
  GElf_Ehdr   ehdr;          /* executable header   */
  Dwarf_Debug dwarf;         /* DWARF handle        */
  Dwarf_Half  dwarf_version; /* DWARF version */
} elf_data_t;


typedef enum {
  MAP_FLAG_f = 0x00,  /* b00 - false, uncertain */
  MAP_FLAG_F = 0x02,  /* b10 - false, certain   */
  MAP_FLAG_t = 0x01,  /* b01 - true , uncertain */
  MAP_FLAG_T = 0x03   /* b11 - true , certain   */
} map_flag_t;

struct btype {
  btype() : code(MAP_FLAG_t), insbound(MAP_FLAG_f), overlapping(MAP_FLAG_f), bbstart(MAP_FLAG_f), funcstart(MAP_FLAG_f), funcend(MAP_FLAG_f), cflow(MAP_FLAG_f), call(MAP_FLAG_f), progentry(MAP_FLAG_f), nop(MAP_FLAG_f) {}
  btype(map_flag_t code_) :   insbound(MAP_FLAG_f), overlapping(MAP_FLAG_f), bbstart(MAP_FLAG_f), funcstart(MAP_FLAG_f), funcend(MAP_FLAG_f), cflow(MAP_FLAG_f), call(MAP_FLAG_f), progentry(MAP_FLAG_f), nop(MAP_FLAG_f)
  {
    code = code_;
  }
  inline bool safe_mark(map_flag_t m, map_flag_t *curr, bool strict = true)
  {
    register bool flag, certain;

    /* we cannot change our mind about a property once we're certain
     * XXX: if the new classification is uncertain, we can safely ignore it, but 
     * if we ever get an assertion failure, it means our certainty assumptions are flawed! */
    flag = (m & 0x01); certain = (m & 0x02);
    if( flag && ((*curr) == MAP_FLAG_F)) { if(strict) bt_assert(!certain); return 0; }
    if(!flag && ((*curr) == MAP_FLAG_T)) { if(strict) bt_assert(!certain); return 0; }

    (*curr) = m;

    return 1;
  }
  
  bool mark(map_flag_t code_, map_flag_t insbound_ = MAP_FLAG_f, map_flag_t bbstart_ = MAP_FLAG_f, 
            map_flag_t funcstart_ = MAP_FLAG_f, map_flag_t funcend_ = MAP_FLAG_f, map_flag_t cflow_ = MAP_FLAG_f,
            map_flag_t call_ = MAP_FLAG_f, map_flag_t progentry_ = MAP_FLAG_f, map_flag_t nop_ = MAP_FLAG_f)
  {
    bool flag;

    /* data bytes cannot have code-like properties */
    flag = (code_ & 0x01);
    assert(!(!flag && (insbound_  & 0x01)));
    assert(!(!flag && (bbstart_   & 0x01)));
    assert(!(!flag && (funcstart_ & 0x01)));
    assert(!(!flag && (funcend_   & 0x01)));
    assert(!(!flag && (cflow_     & 0x01)));
    assert(!(!flag && (call_      & 0x01)));
    assert(!(!flag && (progentry_ & 0x01)));
    assert(!(!flag && (nop_       & 0x01)));

    /* entry points/exit points must start at an instruction boundary */
    flag = (insbound_ & 0x01);
    assert(!(!flag && (bbstart_   & 0x01)));
    assert(!(!flag && (funcstart_ & 0x01)));
    assert(!(!flag && (funcend_   & 0x01)));
    assert(!(!flag && (cflow_     & 0x01)));
    assert(!(!flag && (call_      & 0x01)));
    assert(!(!flag && (progentry_ & 0x01)));
    /*assert(!(!flag && (nop_       & 0x01)));*/

    if(!safe_mark(code_, &code)) return 0;

    /* special treatment if instructions may overlap */
    if(allow_overlapping_ins) {
      if(!safe_mark(insbound_, &insbound, false)) {
        if(insbound_ == MAP_FLAG_T) {
          overlapping = MAP_FLAG_T;
        }
      }
      safe_mark(bbstart_  , &bbstart  , false);
      safe_mark(funcstart_, &funcstart, false);
      safe_mark(funcend_  , &funcend  , false);
      safe_mark(cflow_    , &cflow    , false);
      safe_mark(call_     , &call     , false);
      safe_mark(progentry_, &progentry, false);
      safe_mark(nop_      , &nop      , false);
    } else {
      safe_mark(insbound_ , &insbound);
      safe_mark(bbstart_  , &bbstart);
      safe_mark(funcstart_, &funcstart);
      safe_mark(funcend_  , &funcend);
      safe_mark(cflow_    , &cflow);
      safe_mark(call_     , &call);
      safe_mark(progentry_, &progentry);
      safe_mark(nop_      , &nop);
    }
   
   

    return 1;
  }

  inline bool safe_mark_arm(map_flag_t m, map_flag_t *curr, bool strict = true)
  {
    register bool flag, certain;

    /* we cannot change our mind about a property once we're certain
     * XXX: if the new classification is uncertain, we can safely ignore it, but 
     * if we ever get an assertion failure, it means our certainty assumptions are flawed! */
    /*flag = (m & 0x01); certain = (m & 0x02);
    if( flag && ((*curr) == MAP_FLAG_F)) { if(strict) bt_assert(!certain); return 0; }
    if(!flag && ((*curr) == MAP_FLAG_T)) { if(strict) bt_assert(!certain); return 0; }*/

    (*curr) = m;

    return 1;
  }
   

  bool mark_arm_inst_ori(map_flag_t code_, map_flag_t insbound_ = MAP_FLAG_f, map_flag_t bbstart_ = MAP_FLAG_f, 
            map_flag_t funcstart_ = MAP_FLAG_f, map_flag_t funcend_ = MAP_FLAG_f, map_flag_t cflow_ = MAP_FLAG_f,
            map_flag_t call_ = MAP_FLAG_f, map_flag_t progentry_ = MAP_FLAG_f, map_flag_t nop_ = MAP_FLAG_f)
  {
    bool flag;

    /* data bytes cannot have code-like properties */
    flag = (code_ & 0x01);
    assert(!(!flag && (insbound_  & 0x01)));
    assert(!(!flag && (bbstart_   & 0x01)));
    assert(!(!flag && (funcstart_ & 0x01)));
    assert(!(!flag && (funcend_   & 0x01)));
    assert(!(!flag && (cflow_     & 0x01)));
    assert(!(!flag && (call_      & 0x01)));
    assert(!(!flag && (progentry_ & 0x01)));
    assert(!(!flag && (nop_       & 0x01)));

    /* entry points/exit points must start at an instruction boundary */
    flag = (insbound_ & 0x01);
    assert(!(!flag && (bbstart_   & 0x01)));
    assert(!(!flag && (funcstart_ & 0x01)));
    assert(!(!flag && (funcend_   & 0x01)));
    assert(!(!flag && (cflow_     & 0x01)));
    assert(!(!flag && (call_      & 0x01)));
    assert(!(!flag && (progentry_ & 0x01)));
    /*assert(!(!flag && (nop_       & 0x01)));*/

    if(!safe_mark_arm(code_, &code)) return 0;

    /* special treatment if instructions may overlap */
    if(allow_overlapping_ins) {
      if(!safe_mark_arm(insbound_, &insbound, false)) {
        if(insbound_ == MAP_FLAG_T) {
          overlapping = MAP_FLAG_T;
        }
      }
      //printf("line 281:: 0x%jx ", *this );
      safe_mark_arm(bbstart_  , &bbstart  , false);
      safe_mark_arm(funcstart_, &funcstart, false);
      safe_mark_arm(funcend_  , &funcend  , false);
      safe_mark_arm(cflow_    , &cflow    , false);
      safe_mark_arm(call_     , &call     , false);
      safe_mark_arm(progentry_, &progentry, false);
      safe_mark_arm(nop_      , &nop      , false);
    } else {
      safe_mark_arm(insbound_ , &insbound);
      safe_mark_arm(bbstart_  , &bbstart);
      safe_mark_arm(funcstart_, &funcstart);
      safe_mark_arm(funcend_  , &funcend);
      safe_mark_arm(cflow_    , &cflow);
      safe_mark_arm(call_     , &call);
      safe_mark_arm(progentry_, &progentry);
      safe_mark_arm(nop_      , &nop);
    }

    return 1;
  }

  bool mark_arm_inst(uint64_t addrLoc, map_flag_t code_, map_flag_t insbound_ = MAP_FLAG_f, map_flag_t bbstart_ = MAP_FLAG_f, 
            map_flag_t funcstart_ = MAP_FLAG_f, map_flag_t funcend_ = MAP_FLAG_f, map_flag_t cflow_ = MAP_FLAG_f,
            map_flag_t call_ = MAP_FLAG_f, map_flag_t progentry_ = MAP_FLAG_f, map_flag_t nop_ = MAP_FLAG_f)
  {
    bool flag;

    /* data bytes cannot have code-like properties */
    flag = (code_ & 0x01);
    assert(!(!flag && (insbound_  & 0x01)));
    assert(!(!flag && (bbstart_   & 0x01)));
    assert(!(!flag && (funcstart_ & 0x01)));
    assert(!(!flag && (funcend_   & 0x01)));
    assert(!(!flag && (cflow_     & 0x01)));
    assert(!(!flag && (call_      & 0x01)));
    assert(!(!flag && (progentry_ & 0x01)));
    assert(!(!flag && (nop_       & 0x01)));

    /* entry points/exit points must start at an instruction boundary */
    flag = (insbound_ & 0x01);
    assert(!(!flag && (bbstart_   & 0x01)));
    assert(!(!flag && (funcstart_ & 0x01)));
    assert(!(!flag && (funcend_   & 0x01)));
    assert(!(!flag && (cflow_     & 0x01)));
    assert(!(!flag && (call_      & 0x01)));
    assert(!(!flag && (progentry_ & 0x01)));
    /*assert(!(!flag && (nop_       & 0x01)));*/

    if(!safe_mark_arm(code_, &code)) return 0;

    /* special treatment if instructions may overlap */
    if(allow_overlapping_ins) {
      if(!safe_mark_arm(insbound_, &insbound, false)) {
        if(insbound_ == MAP_FLAG_T) {
          overlapping = MAP_FLAG_T;
        }
      }
      //printf("line 281:: 0x%jx ", *this );
      if (!(BBStartAdd.count(addrLoc) || globalTargets.count(addrLoc)))
      {		safe_mark_arm(bbstart_  , &bbstart  , false); }
      safe_mark_arm(funcstart_, &funcstart, false);
      safe_mark_arm(funcend_  , &funcend  , false);
      safe_mark_arm(cflow_    , &cflow    , false);
      safe_mark_arm(call_     , &call     , false);
      safe_mark_arm(progentry_, &progentry, false);
      safe_mark_arm(nop_      , &nop      , false);
    } else {
      safe_mark_arm(insbound_ , &insbound);
      if (!(BBStartAdd.count(addrLoc) || globalTargets.count(addrLoc)))
      {		safe_mark_arm(bbstart_  , &bbstart); }
      safe_mark_arm(funcstart_, &funcstart);
      safe_mark_arm(funcend_  , &funcend);
      safe_mark_arm(cflow_    , &cflow);
      safe_mark_arm(call_     , &call);
      safe_mark_arm(progentry_, &progentry);
      safe_mark_arm(nop_      , &nop);
    }

    //shaila:if its code then the insbound_ should be true
    /*if (code_ == MAP_FLAG_T || code_ == MAP_FLAG_t)
    {
	if (insbound_ == MAP_FLAG_F || insbound_ == MAP_FLAG_f )
		printf("2.code is true and insbound is false  0x%jx \n", addrLoc);
    }*/

    return 1;
  }

  map_flag_t code;
  map_flag_t insbound;
  map_flag_t overlapping;
  map_flag_t bbstart;
  map_flag_t funcstart;
  map_flag_t funcend;
  map_flag_t cflow;
  map_flag_t call;
  map_flag_t progentry;
  map_flag_t nop;
};
typedef struct btype btype_t;


struct map_range {
  map_range() : addr(0), size(0), btypes() {}
  map_range(uint64_t addr_, uint64_t size_) : btypes()
  {
    addr = addr_;
    size = size_;
  }
  btype_t *get_btype(uint64_t addr_)
  {
    if((addr_ < addr) || (addr_ >= (addr + btypes.size()))) {
      return NULL;
    }
    return &btypes[addr_ - addr];
  }
  uint64_t             addr;   /* start of range            */
  uint64_t             size;   /* length of range           */
  std::vector<btype_t> btypes; /* per-byte type descriptors */
};
typedef struct map_range map_range_t;


#define SEC_TYPE_NONE      0x00
#define SEC_TYPE_PROGBITS  0x01

#define SEC_FLAG_READ   0x01
#define SEC_FLAG_WRITE  0x02
#define SEC_FLAG_EXEC   0x04

struct section_map {
  section_map() : index(0), name(""), type(0), flags(0), addr(0), size(0), map() {}
  uint64_t                 index;  /* section index            */
  std::string              name;   /* section name             */
  uint8_t                  type;   /* type (PROGBITS)          */
  uint8_t                  flags;  /* rwx flags                */
  uint64_t                 off;    /* file offset              */
  uint64_t                 addr;   /* base address             */
  uint64_t                 size;   /* size in bytes            */
  std::set<uint64_t>       dismap; /* disassembled addresses   */
  std::vector<map_range_t> map;    /* code/data map of section */
};
typedef struct section_map section_map_t;


#define SYM_TYPE_FUNC    0x01
#define SYM_TYPE_OBJECT  0x02
#define SYM_TYPE_TLS     0x03

struct symbol {
  symbol(uint8_t type_, char *name_, uint64_t value_, uint64_t size_)
  {
    type  = type_;
    name  = std::string(name_);
    value = value_;
    size  = size_;
  }
  uint8_t     type;
  std::string name;
  uint64_t    value;
  uint64_t    size;
};
typedef struct symbol symbol_t;


struct function {
  function(std::string name_, uint64_t addr_, size_t len_)
  {
    char *demangled;

    demangled = cplus_demangle(name_.c_str(), DMGL_NO_OPTS);
    if(demangled) {
      name = std::string(demangled);
      free(demangled);
    } else {
      name = name_;
    }

    mangled_name = name_;
    cu_path      = "";
    base         = addr_;
    ranges.push_back(std::pair<uint64_t, size_t>(addr_, len_));
    startline    = 0;
    endline      = 0;
    valid_sig    = false;
    ret          = "int";
    callconv     = "";
    inlined      = false;
    nothrow      = false;
    noret        = false;
    addrtaken    = false;
    dead         = false;
    multiret     = false;

    verbose(2, "created function %s (%s) @ 0x%jx (%zu)", name.c_str(), mangled_name.c_str(), base, len_);
  }
  std::string                  name;                 /* function name                  */
  std::string                  mangled_name;         /* mangled function name          */
  std::string                  cu_path;              /* path to compile unit           */
  uint64_t                     base;                 /* base address                   */
  std::vector< std::pair<uint64_t, size_t> > ranges; /* address ranges                 */
  unsigned                     startline;            /* first line nr of function      */
  unsigned                     endline;              /* last line nr of function       */
  std::map<unsigned, uint64_t> line2addr;            /* line numbers in cu to addrs    */
  std::map<uint64_t, unsigned> addr2line;            /* addrs to line numbers in cu    */
  bool                         valid_sig;            /* return/param types are set     */
  std::string                  ret;                  /* return type                    */
  std::vector<std::string>     params;               /* parameter types                */
  std::vector<std::string>     attributes;           /* function attributes            */
  std::string                  callconv;             /* calling convention             */
  bool                         inlined;              /* true if func is inlined        */
  bool                         nothrow;              /* true if func does not throw    */
  bool                         noret;                /* true if func never returns     */
  bool                         addrtaken;            /* true if func is address taken  */
  bool                         dead;                 /* true if func is trivially dead */
  bool                         multiret;             /* true if func calls multiret fn */
};
typedef struct function function_t;


typedef struct {
  uint64_t    addr; /* address of the overlap (NOT starting address of BB) */
  function_t *f;    /* overlapping function (overlaps g)                   */
  function_t *g;    /* overlapped  function (overlapped by f)              */
} overlapping_bb_t;


typedef struct {
  std::string funcname;
  std::string cu_path;
  unsigned    start_line;
  uint64_t    start_addr;
  unsigned    end_line;
  uint64_t    end_addr;
} address_taken_bb_t;


typedef struct {
  std::string           cu_path;
  unsigned              start_line;
  uint64_t              start_addr;
  std::vector<unsigned> case_lines;
  std::vector<uint64_t> case_addrs;
  unsigned              default_line;
  uint64_t              default_addr;
} switch_t;


void
verbose(int level, char const *fmt, ...)
{
  va_list args;

  if(verbosity >= level) {
    va_start(args, fmt);
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
  }
}


void
print_warn(char const *fmt, ...)
{
  va_list args;

  if(warnings) {
    va_start(args, fmt);
    fprintf(ERROUT, "WARNING: ");
    vfprintf(ERROUT, fmt, args);
    fprintf(ERROUT, "\n");
    va_end(args);
  }
}


void
print_err(char const *fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  fprintf(ERROUT, "ERROR: ");
  vfprintf(ERROUT, fmt, args);
  fprintf(ERROUT, "\n");
  va_end(args);
}


std::string
str_realpath(std::string s)
{
  char real[PATH_MAX];

  if(!realpath(s.c_str(), real)) {
    return "";
  }
  return std::string(real);
}


unsigned long
hash_str_to_int(std::string s)
{
  unsigned long h;

  h = 5381;
  for(auto cc : s) {
    h = (h << 5) + h + cc;
  }

  return h;
}


std::string
hash_path(std::string s)
{
  char *c, *bname;
  std::string hash;
  unsigned long h;
  std::stringstream stream;

  h = 5381;
  for(auto cc : s) {
    h = (h << 5) + h + cc;
  }
  stream << std::hex << h;

  c = strdup(s.c_str());
  if(!c) {
    return "";
  }
  bname = basename(c);
  hash = "h" + stream.str().substr(0, 6) + "_" + std::string(bname);
  std::replace(hash.begin(), hash.end(), '.', '_');
  free(c);

  return hash;
}


std::string
vecjoin(std::vector<std::string> *v, std::string sep)
{
  size_t i;
  std::stringstream ss;

  for(i = 0; i < v->size(); i++) {
    if(i > 0) {
      ss << sep;
    }
    ss << v->at(i);
  }

  return ss.str();
}


void
__bt_assert(bool c)
{
#ifndef NDEBUG
  int i, p, tracelen;
  void *trace[32];
  char **msg, cmd[256];

  if(!c) {
    print_err("Assertion failed");

    tracelen = backtrace(trace, 32);
    msg = backtrace_symbols(trace, tracelen);
    if(!msg) {
      print_err("failed to get backtrace");
      exit(1);
    }

    for(i = 0; i < tracelen; i++) {
      fprintf(ERROUT, "    #%d %s", i, msg[i]);
      p = 0;
      while(msg[i][p] != '(' && msg[i][p] != ' ' && msg[i][p] != 0) {
        p++;
      }
      sprintf(cmd, "addr2line %p -e %.*s 1>&2", trace[i], p, msg[i]);
      if(system(cmd) != 0) {
      }
    }

    exit(1);
  }
#endif
}


char*
safe_diename(char *diename)
{
  return diename ? diename : (char*)DWARF_DIENAME_NONE;
}


int
resolve_dwarf_die_ref(Dwarf_Debug dwarf, Dwarf_Attribute attr, Dwarf_Die *res, char const **err)
{
  Dwarf_Error dwerr;
  Dwarf_Half attrform;
  Dwarf_Off off;

  if(dwarf_whatform(attr, &attrform, &dwerr) != DW_DLV_OK) {
    (*err) = "failed to get DWARF attribute form";
    return -1;
  }

  switch(attrform) {
  case DW_FORM_ref1:
  case DW_FORM_ref2:
  case DW_FORM_ref4:
  case DW_FORM_ref8:
  case DW_FORM_ref_udata:
    if(dwarf_formref(attr, &off, &dwerr) != DW_DLV_OK) {
      (*err) = "dwarf_formref() failed";
      return -1;
    }
    break;
  case DW_FORM_ref_addr:
    if(dwarf_global_formref(attr, &off, &dwerr) != DW_DLV_OK) {
      (*err) = "dwarf_global_formref() failed";
      return -1;
    }
    break;
  default:
    (*err) = "unrecognized form for DWARF attribute (1)";
    return -1;
  }

  if(dwarf_offdie(dwarf, off, res, &dwerr) != DW_DLV_OK) {
    //printf(" failed to resolve DWARF entry reference\n"); //mine
    (*err) = "failed to resolve DWARF entry reference"; 
    return -1; 
  }

  return 0;
}


int
resolve_dwarf_high_pc(Dwarf_Attribute attr, uint64_t *res, bool *rel, char const **err)
{
  Dwarf_Error dwerr;
  Dwarf_Half attrform;

  if(dwarf_whatform(attr, &attrform, &dwerr) != DW_DLV_OK) {
    (*err) = "failed to get DWARF attribute form";
    return -1;
  }

  switch(attrform) {
  case DW_FORM_addr:
    if(dwarf_formaddr(attr, (Dwarf_Addr*)res, &dwerr) != DW_DLV_OK) {
      (*err) = "dwarf_formaddr() failed";
      return -1;
    }
    (*rel) = false;
    break;
  case DW_FORM_data1:
  case DW_FORM_data2:
  case DW_FORM_data4:
  case DW_FORM_data8:
  case DW_FORM_udata:
    if(dwarf_formudata(attr, (Dwarf_Unsigned*)res, &dwerr) != DW_DLV_OK) {
      (*err) = "dwarf_formudata() failed";
      return -1;
    }
    (*rel) = true;
    break;
  default:
    (*err) = "unrecognized form for DWARF attribute (2)";
    return -1;
  }

  return 0;
}


bool
addr_in_map_range(map_range_t *range, uint64_t addr)
{
  return (addr >= range->addr) && (addr < (range->addr + range->size));
}


map_range_t*
map_range_by_addr(section_map_t *smap, uint64_t addr)
{
  size_t i;

  for(i = 0; i < smap->map.size(); i++) {
    if(addr_in_map_range(&smap->map[i], addr)) {
      return &smap->map[i];
    }
  }

  return NULL;
}


inline bool
addr_in_section_map(section_map_t *smap, uint64_t addr)
{
  return (addr >= smap->addr) && (addr < (smap->addr + smap->size));
}


section_map_t*
section_map_by_addr(std::vector<section_map_t> *smaps, uint64_t addr)
{
  register size_t i;

  for(i = 0; i < smaps->size(); i++) {
    if(addr_in_section_map(&smaps->at(i), addr)) {
      return &smaps->at(i);
    }
  }

  return NULL;
}


map_range_t*
section_map_range_by_addr(std::vector<section_map_t> *smaps, uint64_t addr)
{
  section_map_t *s;

  s = section_map_by_addr(smaps, addr);
  if(s) {
    return map_range_by_addr(s, addr);
  } else {
    return NULL;
  }
}


btype_t*
btype_by_addr(std::vector<section_map_t> *smaps, uint64_t addr)
{
  map_range_t *map;
  btype_t *b;

  map = section_map_range_by_addr(smaps, addr);
  if(!map) {
    return NULL;
  }
  b = map->get_btype(addr);
  assert(b);

  return b;
}

//myFunction: print the machine architecture used in the binary
int
printMacArchi(elf_data_t *elf, char const **err)
{
	int ret=0;
	switch(elf->ehdr.e_machine) 
	{
  		case EM_386:
			ret=1;
			printf("Arch Type :: EM_386\n");
			break;
  		case EM_X86_64:
			ret=2;
			printf("Arch Type :: EM_X86_64\n");
			break;
		case EM_ARM:
			ret=3;
			printf("Arch Type :: EM_ARM\n");
    			break;
		case EM_AARCH64:
			ret=4;
			printf("Arch Type :: EM_AARCH64\n");
			break;
		case EM_MIPS:
			ret=5;
			printf("Arch Type :: EM_MIPS\n");
			break;
  		default:
    			(*err) = "unsupported instruction set";
   			ret=-1;
 	}

	return ret;

}
//myFunction: print the machine architecture used in the binary


//myFunction: find the machine architecture used in the binary
int
getMacArchi(elf_data_t *elf, char const **err)
{
	int ret=0;
	switch(elf->ehdr.e_machine) 
	{
  		case EM_386:
			ret=1;
			break;
  		case EM_X86_64:
			ret=2;
			break;
		case EM_ARM:
			ret=3;
    			break;
		case EM_AARCH64:
			ret=4;
			break;
		case EM_MIPS:
			ret=5;
			break;
  		default:
    			(*err) = "unsupported instruction set";
   			ret=-1;
 	}

	return ret;

}

int
open_elf(int fd, elf_data_t *elf, char const **err)
{
  int ret;

  elf->fd = fd;
  elf->e  = NULL;

  if(elf_version(EV_CURRENT) == EV_NONE) {
    (*err) = "failed to initialize libelf";
    goto fail;
  }

  elf->e = elf_begin(elf->fd, ELF_C_READ, NULL);
  if(!elf->e) {
    (*err) = "failed to open ELF file";
    goto fail;
  }

  if(elf_kind(elf->e) != ELF_K_ELF) {
    switch(elf_kind(elf->e)) {
    case ELF_K_AR:
      fprintf(stderr, "elf_kind=ELF_K_AR\n");
      break;
    case ELF_K_COFF:
      fprintf(stderr, "elf_kind=ELF_K_COFF\n");
      break;
    case ELF_K_ELF:
      fprintf(stderr, "elf_kind=ELF_K_ELF\n");
      break;
    case ELF_K_NONE:
    default:
      fprintf(stderr, "elf_kind=ELF_K_NONE\n");
      break;
    }
    (*err) = "not an ELF executable";
    goto fail;
  }

  ret = gelf_getclass(elf->e);
  switch(ret) {
  case ELFCLASSNONE:
    (*err) = "unknown ELF class";
    goto fail;

  case ELFCLASS32:
    elf->bits = 32;
    break;

  default:
    elf->bits = 64;
    break;
  }

  if(!gelf_getehdr(elf->e, &elf->ehdr)) {
    (*err) = "failed to get executable header";
    goto fail;
  }

  elf->entry = elf->ehdr.e_entry;
  elf->dwarf = NULL;

  switch(elf->ehdr.e_machine) {
  case EM_386:
  case EM_X86_64:
  case EM_ARM:
  case EM_MIPS:
    /* supported */
    break;
  default:
    (*err) = "unsupported instruction set";
    goto fail;
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}


int
close_elf(elf_data_t *elf)
{
  if(elf->e) {
    elf_end(elf->e);
  }

  return 0;
}


int
read_elf_section_by_off(elf_data_t *elf, off_t off, uint8_t *dst, size_t *len, char const **err)
{
  int ret;
  off_t saved_off;

  saved_off = lseek(elf->fd, 0, SEEK_CUR);

  if(lseek(elf->fd, off, SEEK_SET) != off) {
    (*err) = "failed to seek to offset in ELF binary";
    goto fail;
  }

  (*len) = read(elf->fd, dst, (*len));
  if((*len) < 1) {
    (*err) = "failed to read bytes from ELF binary";
    goto fail;
  }

  if(lseek(elf->fd, saved_off, SEEK_SET) != saved_off) {
    (*err) = "failed to seek to offset in ELF binary";
    goto fail;
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}


int
read_elf_section_by_addr(elf_data_t *elf, std::vector<section_map_t> *smaps, uint64_t addr, uint8_t *dst, size_t *len, char const **err)
{
  int ret;
  off_t saved_off, off;
  section_map_t *sec;

  saved_off = lseek(elf->fd, 0, SEEK_CUR);

  sec = section_map_by_addr(smaps, addr);
  if(!sec) {
    //(*err) = "address points outside mapped sections (1)"; //original
    //goto fail;
    return 0; //shaila code
  }

  off = sec->off + (addr - sec->addr);
  if(lseek(elf->fd, off, SEEK_SET) != off) {
    (*err) = "failed to seek to offset in ELF binary";
    goto fail;
  }

  (*len) = read(elf->fd, dst, (*len));
  if((*len) < 1) {
    (*err) = "failed to read bytes from ELF binary";
    goto fail;
  }

  if(lseek(elf->fd, saved_off, SEEK_SET) != saved_off) {
    (*err) = "failed to seek to offset in ELF binary";
    goto fail;
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}


uint64_t
is_cs_BBMarkData_ARM_ins(uint64_t BBLoc,std::vector<section_map_t> *smaps,int ret, int cflow, int call, int nop)
{
	int marked=0;
	btype_t *b;
	/* ins->address is definitely an instruction boundary  markinf data sections*/
	/*if (BBLoc==4197968)
        {	printf("0x%jx  nop:%d ret:%d cflow:%d call:%d\n", BBLoc ,nop,ret,cflow,call);}*/
        b = btype_by_addr(smaps, BBLoc);
        if(!b) 
	{
        	print_warn("WARNING::suspected code byte at 0x%jx is outside selected sections", BBLoc);
    	}
        b = btype_by_addr(smaps, BBLoc);
	//printf("1031::0x%jx  1031:0x%jx\n", *b , btype_by_addr(smaps, BBLoc));
        marked = b->mark_arm_inst(BBLoc,MAP_FLAG_T, MAP_FLAG_T, MAP_FLAG_T, b->funcstart, ret ? MAP_FLAG_t : b->funcend, cflow ? MAP_FLAG_T : MAP_FLAG_F, call ? MAP_FLAG_T : MAP_FLAG_F, b->progentry, nop ? MAP_FLAG_T : MAP_FLAG_F);
	for(int i = BBLoc+1; i < BBLoc+4; i++) {
      		b = btype_by_addr(smaps, i);
		marked = b->mark_arm_inst(i,MAP_FLAG_T, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, nop ? MAP_FLAG_T : MAP_FLAG_F);
	}
	return marked;
}

uint64_t
is_cs_LDRMarkData_ARM_ins(uint64_t dataLoc,std::vector<section_map_t> *smaps)
{
	int marked=0;
	btype_t *b;
	/* ins->address is definitely an instruction boundary  markinf data sections*/
        b = btype_by_addr(smaps, dataLoc);
        if(!b) 
	{
        	print_warn("WARNING::suspected code byte at 0x%jx is outside selected sections", dataLoc);
    	}
	
	for(int i = dataLoc; i < dataLoc+4; i++) {
      		b = btype_by_addr(smaps, i);
		marked = b->mark_arm_inst(i,MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F,MAP_FLAG_F,MAP_FLAG_F,MAP_FLAG_F);
		//marked = b->mark(MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F,MAP_FLAG_F,MAP_FLAG_F,MAP_FLAG_F);
		//printf("marked :: 0x%d   \n ", marked);
	}
	return marked;
}




uint64_t
is_cs_ARM_INS_ADD(cs_insn *ins,std::vector<section_map_t> *smaps)
{
	char *opStr;
	char **tokens;
	//char *firstReg;
	char firstReg[12];
	//char *pc;
	char pc[12];
	//char *hexOffset;
	char hexOffset[12];

	int firstComma=0,secondComma=0,dataAddrLocOff=0;
	uint64_t dataAddrLoc =0;
	//Assuming this kinda instruction add  r3, pc, #0x90, this instr is usually followed by ldm r3,{r6,r3}
	opStr = {ins->op_str};
	if (strstr({ins->op_str}, "#0x") != NULL) 
	{
		for(int i = 0; i < strlen(opStr); i++)
		{
			if(opStr[i] == ',' && firstComma==0)
				firstComma=i;
			if(opStr[i] == ',' && firstComma!=0)
				secondComma=i;
				
		}

		strncpy(firstReg, opStr, firstComma);
		firstReg[firstComma] = '\0' ;
		
		strncpy(pc, opStr+firstComma+2, secondComma - firstComma -2);
		pc[secondComma - firstComma -2] = '\0';

		strncpy(hexOffset, opStr+secondComma+5, strlen(opStr) -1 - secondComma -4);
		hexOffset[strlen(opStr) -1 - secondComma -4] =  '\0';

		
		dataAddrLocOff = (int)strtol(hexOffset, NULL, 16); 
		//for first 4 bytes
		dataAddrLoc =ins->address + (uint64_t)dataAddrLocOff +8; 
		DataAddInCodeSeg.insert(dataAddrLoc);
		is_cs_LDRMarkData_ARM_ins(dataAddrLoc,smaps);
		//for first 4 bytes
		dataAddrLoc =dataAddrLoc +4;
		DataAddInCodeSeg.insert(dataAddrLoc);
		is_cs_LDRMarkData_ARM_ins(dataAddrLoc,smaps);
	}
	
	if (strstr({ins->op_str}, "#-0x") != NULL)
	{
		for(int i = 0; i < strlen(opStr); i++)
		{
			if(opStr[i] == ',' && firstComma==0)
				firstComma=i;
			if(opStr[i] == ',' && firstComma!=0)
				secondComma=i;
		}

		strncpy(firstReg, opStr, firstComma);
		firstReg[firstComma] = '\0' ;
		
		strncpy(pc, opStr+firstComma+2, secondComma - firstComma -2);
		pc[secondComma - firstComma -2] = '\0';

		strncpy(hexOffset, opStr+secondComma+6, strlen(opStr) -1 - secondComma -4);
		hexOffset[strlen(opStr) -1 - secondComma -4] =  '\0';

		
		dataAddrLocOff = (int)strtol(hexOffset, NULL, 16); 
		//for first 4 bytes
		dataAddrLoc =ins->address - (uint64_t)dataAddrLocOff +8; 
		DataAddInCodeSeg.insert(dataAddrLoc);
		is_cs_LDRMarkData_ARM_ins(dataAddrLoc,smaps);
		//for first 4 bytes
		dataAddrLoc =dataAddrLoc +4;
		DataAddInCodeSeg.insert(dataAddrLoc);
		is_cs_LDRMarkData_ARM_ins(dataAddrLoc,smaps);
	}


}


uint64_t
is_cs_LDR_ARM_ins(cs_insn *ins,std::vector<section_map_t> *smaps)
{
	char *opStr,*result;
	char dest[12];
	int position,substringLength,dataAddrLocOff;
	uint64_t dataAddrLoc =0;
	uint64_t immVal=-1,reg=-1;
	cs_arm_op *armop;
	
	if(ins->id == ARM_INS_LDR)
	{	
		opStr = {ins->op_str};
		if(strstr(opStr, ", [pc]") != NULL)
		{
			//printf(", [pc]::\n ");
			dataAddrLoc =ins->address + 8;
			DataAddInCodeSeg.insert(dataAddrLoc);
			is_cs_LDRMarkData_ARM_ins(dataAddrLoc,smaps);
			return 1;
		}
		if(strstr(opStr, "[pc, #-0x") != NULL)
		{
			result= strstr(opStr, "[pc, #");
			position = result - opStr;
			substringLength = strlen(opStr) - position;
                        if (position>0 && substringLength>0)
			{
				strncpy(dest, opStr+position+9, substringLength-9-1);
			}
			dest[substringLength-9-1] = '\0' ;
			dataAddrLocOff = (int)strtol(dest, NULL, 16); 
			dataAddrLoc =ins->address - (uint64_t)dataAddrLocOff +8;
			DataAddInCodeSeg.insert(dataAddrLoc);
			is_cs_LDRMarkData_ARM_ins(dataAddrLoc,smaps);
			return 1;
		}
		else if (strstr(opStr, "[pc, #0x") != NULL) 
		{
			result= strstr(opStr, "[pc, #");
			position = result - opStr;
			substringLength = strlen(opStr) - position;
                        if (position>0 && substringLength>0)
			{
				strncpy(dest, opStr+position+8, substringLength-8-1);
			}
			dest[substringLength-8-1] = '\0' ;
			dataAddrLocOff = (int)strtol(dest, NULL, 16); 
			dataAddrLoc =ins->address + (uint64_t)dataAddrLocOff +8;
			DataAddInCodeSeg.insert(dataAddrLoc);
			is_cs_LDRMarkData_ARM_ins(dataAddrLoc,smaps);
			return 1;
		}
		else if (strstr(opStr, "[pc, #-") != NULL)
		{
			result= strstr(opStr, "[pc, #");
			position = result - opStr;
			substringLength = strlen(opStr) - position;
                        if (position>0 && substringLength>0)
			{
				strncpy(dest, opStr+position+7, substringLength-7-1);
			}
			dest[substringLength-7-1] = '\0' ;
			dataAddrLocOff = (int)strtol(dest, NULL, 16); 
			dataAddrLoc =ins->address - (uint64_t)dataAddrLocOff +8;
			DataAddInCodeSeg.insert(dataAddrLoc);
			is_cs_LDRMarkData_ARM_ins(dataAddrLoc,smaps);
			return 1;
		}
		else if (strstr(opStr, "[pc, #") != NULL)
		{
			result= strstr(opStr, "[pc, #");
			position = result - opStr;
			substringLength = strlen(opStr) - position;
                        if (position>0 && substringLength>0)
			{
				strncpy(dest, opStr+position+6, substringLength-6-1);
			}
			dest[substringLength-6-1] = '\0' ;
			dataAddrLocOff = (int)strtol(dest, NULL, 16);  
			dataAddrLoc =ins->address + (uint64_t)dataAddrLocOff +8;
			DataAddInCodeSeg.insert(dataAddrLoc);
			is_cs_LDRMarkData_ARM_ins(dataAddrLoc,smaps);
			return 1;
		}
		else
		{
			//printf("CMP ARM addr:: 0x%jx   %s  %s\n ", ins->address, ins->mnemonic, ins->op_str);
			for(int j = 0; j < ins->detail->arm.op_count; j++) 
			{
				armop = &ins->detail->arm.operands[j];
		  		if(armop->type == ARM_OP_IMM) 
		    		{	immVal = armop->imm;
					//cmpRegMapForArm.insert(std::pair<int64_t,int64_t>(reg, immVal));
		                        //cmpRegMapForArm.insert({ reg,  immVal }); 
					cmpRegMapForArm[reg] = immVal;
					//if (ins->address==321140)
					//	printf("1351::Reg::%d  immVal::%d\n ",reg, immVal);
					/* for(std::map<int,int>::iterator it = cmpRegMapForArm.begin(); it != cmpRegMapForArm.end(); ++it) 
					{
						printf("Reg::%d   Val::%d",it->first,it->second);
					}*/
				}
				if(armop->type == ARM_OP_REG) 
		    		{
					if (reg==-1)
						reg = armop->reg-66; //CMP firstReg,secondReg
					//if (ins->address==321152)
					//	printf("Register::%d\n ", reg);
				}
			}
			return 0;
		}
	}

	
        return 0;

}

//function looks for immediate values compared against registers 
//to find jump table data section in the code segment
int 
is_cs_CMP_ins(cs_insn *ins)
{
	uint64_t immVal=-1,reg=-1,reg2=-1;
	cs_arm_op *armop;
	
	if(ins->id == ARM_INS_CMP)
	{
		//printf("CMP ARM addr:: 0x%jx   %s  %s\n ", ins->address, ins->mnemonic, ins->op_str);
		for(int j = 0; j < ins->detail->arm.op_count; j++) 
		{
			armop = &ins->detail->arm.operands[j];
          		if(armop->type == ARM_OP_IMM) 
            		{	immVal = armop->imm;
				//cmpRegMapForArm.insert(std::pair<int64_t,int64_t>(reg, immVal));
                                //cmpRegMapForArm.insert({ reg,  immVal }); 
				cmpRegMapForArm[reg] = immVal;
				/* for(std::map<int,int>::iterator it = cmpRegMapForArm.begin(); it != cmpRegMapForArm.end(); ++it) 
        			{
					printf("Reg::%d   Val::%d",it->first,it->second);
        			}*/
			}
			if(armop->type == ARM_OP_REG) 
            		{
				if (reg==-1)
					reg = armop->reg-66; //CMP firstReg,secondReg
				else
					reg2 = armop->reg-66;
				//if (ins->address==321152)
				//	printf("Register::%d\n ", reg);
			}
		
			/*if (ins->address==124772)
				printf("immVal::%d   Reg::%d  Reg2::%d\n ", immVal, reg,reg2);*/
		}
		if (reg!=-1 && reg2!=-1)
		{
			//reg == reg2
			cmpRegMapForArm[reg] = cmpRegMapForArm[reg2];
		}
	}
}


int
is_cs_LDRLS_ARM_ins2(std::vector<section_map_t> *smaps, cs_insn *ins)
{
	cs_arm_op *armop;
        uint64_t jmpTableAddr;
        char *opStr = {ins->op_str};
        char *result = strstr(opStr, ", [pc, #");
	if (result == NULL)
		return 0;
	char *result1 = strstr(opStr, "#");
	if (result1 == NULL)
		return 0;
	char *result2 = strstr(opStr, "]");
	if (result2 == NULL)
		return 0;
	//printf("****0x%jx    %s\n", ins->address,ins->mnemonic);
	//printf("%d   \n",  *(ins->bytes)); //works
	//printf("0x%jx  0x%jx 0x%jx 0x%jx \n",  *(ins->bytes), *((ins+1)->bytes), *((ins+2)->bytes), *((ins+3)->bytes));
	//printf(ins->bytes); //gives the type of this //‘uint8_t* {aka unsigned char*}’ to ‘const char*’ [-fpermissive]
	//printf("%d   \n",  *(ins->bytes)); //works
	//printf("0x%jx  0x%jx 0x%jx 0x%jx \n",  *(ins->bytes), *((ins+1)->bytes), *((ins+2)->bytes), *((ins+3)->bytes));
	//printf("DEBUG33\n");
	//printf("result111::%s\n", result);
	//printf("result222::%s\n", result1);
	//printf("result333::%s\n", result2);
	//char dest[12];
	//char *dest;
    	int position = result - opStr;
	int position1 = result1 - opStr;
	int position2 = result2 - opStr;
    	int substringLength = strlen(opStr) - position;
	//printf("DEBUG34\n");
        //printf("position::%d  position1::%d  position2::%d  substringLength::%d \n", position,position1,position2,substringLength);
	btype_t *b;
	//printf("DEBUG35\n");
	//strncpy(dest, opStr+position+10, substringLength-1-10);
	//strtab_buf = (char*)malloc(position2-position1);
	char dest[position2-position1];
	strncpy(dest, opStr+position1+1, position2-position1-1);
	//strncpy(dest, opStr+position1+1, position2-position1);
	
	//printf("DEBUG36\n");
	//char *token = strtok(dest,"U");
	//char *token = strtok(dest,"]"); 
    	//int num = (int)strtol(token, NULL, 16);     // number base 16   
	
	char *token = strtok(dest,"U");
	//printf("dest::%s\n", dest); 
	//printf("token::%s\n", token);
	int num = (int)strtol(dest, NULL, 16);   
	int num1 = (int)strtol(token, NULL, 16);             
    	//printf("Num::%d\n", num); //3
	//printf("Num1::%d\n", num1); //3
	//printf("DEBUG37\n");
	jmpTableAddr = ins->address + 8 +  num;
	DataAddInCodeSeg.insert(jmpTableAddr);
	//printf("jmpTableAddr:: 0x%jx \n ", jmpTableAddr);
	//strncpy(dest, opStr+position+10, substringLength-1-10); //to cause error
	return 1;
}
//mark the BB for the conditional / unconditional jumps
int 
markBBForTargets (std::vector<section_map_t> *smaps,uint64_t targetAdd)
{
	btype_t *updateBBb;

	updateBBb = btype_by_addr(smaps, targetAdd);
	if(!updateBBb) 
	{
		return 0;
	}
	updateBBb->bbstart = MAP_FLAG_T;
	return 1;
       
}
int
is_cs_LDRLS_ARM_ins(std::vector<section_map_t> *smaps, cs_insn *ins, InstrInfo *instInfoStruct)
{

	cs_arm_op *armop;
        uint64_t jmpTableAddr;
        char *opStr = {ins->op_str};
        char *result = strstr(opStr, "pc, [pc, ");
        //printf("result::%s\n", result);
        if (result == NULL)
		return 0;
    	char dest[12];
    	int position = result - opStr;
    	int substringLength = strlen(opStr) - position;
	btype_t *b;
	strncpy(dest, opStr+position+10, 1);
        
	//printf("is_cs_LDRLS_ins::%s\n", dest); //causes error
	//printf("****0x%jx    %s\n", ins->address,ins->mnemonic);
	//printf("%d   \n",  *(ins->bytes)); //works
	//printf("0x%jx  0x%jx 0x%jx 0x%jx \n",  *(ins->bytes), *((ins+1)->bytes), *((ins+2)->bytes), *((ins+3)->bytes));
        char *token = strtok(dest,"U"); 
    	int num = (int)strtol(token, NULL, 16);     // number base 16  
	if (strcmp(dest, "r") == 0)
       	{
          num=-56;
       	}                   
    	//printf("Num::%d\n", num); //3
        //get the latest value compared to this register
	int switchCasesNo = cmpRegMapForArm.find(num)->second;
        //printf("switchCasesNo::%d\n", switchCasesNo); //11
        //printing the map
        /*for(std::map<int,int>::iterator it = cmpRegMapForArm.begin(); it != cmpRegMapForArm.end(); ++it) 
        {
		printf("Reg::%d   Val::%d",it->first,it->second);
        }*/
        for (int i=0 ;i<=switchCasesNo;i++)
        {
		jmpTableAddr = ins->address + 8 +  i*4;
		DataAddInCodeSeg.insert(jmpTableAddr);
		
		b = btype_by_addr(smaps,jmpTableAddr );
		if(!b) 
		{
			printf("is_cs_LDRLS_ARM_ins - cannot find btype\n");
		}
	        verbose(2, "marking instruction boundary (1) at 0x%jx", jmpTableAddr );
		b->mark(MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F,MAP_FLAG_F,MAP_FLAG_F,MAP_FLAG_F);
		
		//marking the whole inst as data
		for(int i = 1; i < 4; i++) 
		{
	      		b = btype_by_addr(smaps,jmpTableAddr+i);
			b->mark(MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F,MAP_FLAG_F,MAP_FLAG_F,MAP_FLAG_F);
			//marked = b->mark(MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F,MAP_FLAG_F,MAP_FLAG_F,MAP_FLAG_F);
			//printf("marked :: 0x%d   \n ", marked);
		}
		//marking the whole inst as data

		//we will mark the BB pointed to by the jump table (ie. the jump address targets)
		std::map<uint64_t,uint64_t>::iterator byteIt = instBytesMap.find(jmpTableAddr);
		if (byteIt!=instBytesMap.end())
		{
			BBStartAdd.insert(instBytesMap[jmpTableAddr]); //instr after conditional jump target
			markBBForTargets (smaps,instBytesMap[jmpTableAddr]);
			//printf("****ldrls  markBBForTargets  jmptableadd::0x%jx    \n", instBytesMap[jmpTableAddr]);
			//we should store this jumpAddTarget as CFGInfo too - it should be in the map alr
			instInfoStruct->targetSet.insert(instBytesMap[jmpTableAddr]);
			/*if(ins->address>=321164 && ins->address<=322708)
			{	
		//printf("ins->address::0x%jx  *(ins->bytes+ 2)::0x%jx   *(ins->bytes+ 1)::0x%jx  *(ins->bytes)::0x%jx \n", ins->address,*(ins->bytes+2),*(ins->bytes+1),*(ins->bytes));
				printf(" 1523::marking the BBs ...ins->address::0x%jx    targetJumpAdd::0x%jx\n", jmpTableAddr,instBytesMap[jmpTableAddr]);
			}*/
			//printf("ins->address::0x%jx   %d \n", ins->address,InstrInfoMaps[ins->address].targetSet.size());
			//if(jmpTableAddr>=124748 && jmpTableAddr<=124856)			
			//	printf("jmpTableAddr::0x%jx  targetJumpAdd::0x%jx\n",jmpTableAddr,instBytesMap[jmpTableAddr]);
		}
		/*else
		{
			//printf("jmpTableAddr::0x%jx  no targetJumpAdd found...\n",jmpTableAddr);
			if(jmpTableAddr>=124748 && jmpTableAddr<=124856)
			{	
				printf("not found marking the BBs ...jmpTableAddrjmpTableAddr::0x%jx  switchCasesNo::%d dest::%s num::%d i::%d\n", jmpTableAddr,switchCasesNo,dest,num,i);
			}
		}*/
		jmpTableAddresses.insert(jmpTableAddr);	
		//printf("****jmpTableAddresses.insert(jmpTableAddr),jmpTableAddr::0x%jx    \n", jmpTableAddr);
        }
	return 1;
	//printf("LDRLS ARM addr:: 0x%jx   %s  %s\n ", ins->address, ins->mnemonic, ins->op_str);
	/*cs_arm_op *armop;
        uint64_t jmpTableAddr;
        char *opStr = {ins->op_str};
        char *result = strstr(opStr, "pc, [pc, ");
    	char dest[12];
    	int position = result - opStr;
    	int substringLength = strlen(opStr) - position;
	strncpy(dest, opStr+position+10, 1);
	//printf("is_cs_LDRLS_ins::%s\n", dest); //causes error
        char *token = strtok(dest,"U"); 
    	int num = (int)strtol(token, NULL, 16);     // number base 16                     
    	printf("Num::%d\n", num); //3
        //get the latest value compared to this register
	int switchCasesNo = cmpRegMapForArm.find(num)->second;
        printf("switchCasesNo::%d\n", switchCasesNo); //11
        //printing the map
        //for(std::map<int,int>::iterator it = cmpRegMapForArm.begin(); it != cmpRegMapForArm.end(); ++it) 
        //{
	//	printf("Reg::%d   Val::%d",it->first,it->second);
        //}
        for (int i=0 ;i<=switchCasesNo;i++)
        {
		jmpTableAddr = ins->address + 8 +  i*4;
		DataAddInCodeSeg.insert(jmpTableAddr);
        }*/

}

int
is_cs_nop_X86_ins(cs_insn *ins)
{
  switch(ins->id) 
  {
  case X86_INS_NOP:
  case X86_INS_FNOP:
    return 1;
  default:
    return 0;
  }
}

int
is_cs_nop_ARM_ins(cs_insn *ins)
{
  switch(ins->id) 
  {
  case ARM_INS_NOP:
    return 1;
  default:
  {
    //mov r0, r0 instruction is the same as NOP
    if(ins->id ==ARM_INS_MOV &&  strcmp(ins->mnemonic, "mov")==0  &&(strstr({ins->op_str}, "r0, r0") != NULL))
    {
	//printf("****0x%jx    %s   %s \n", ins->address,ins->mnemonic,ins->op_str);
	return 1;
    }

    if(strcmp(ins->mnemonic, "andeq")==0  &&(strstr({ins->op_str}, "r0, r0, r0") != NULL))
    {
	//printf("****0x%jx    %s   %s \n", ins->address,ins->mnemonic,ins->op_str);
	return 1;
    }
    return 0;
  }
  }
}


int
is_cs_nop_MIPS_ins(cs_insn *ins)
{
  switch(ins->id) 
  {
  case MIPS_INS_NOP:
    return 1;
  default:
    return 0;
  }
}

int
is_cs_cflow_group(uint8_t g)
{
  return (g == CS_GRP_JUMP) || (g == CS_GRP_CALL) || (g == CS_GRP_RET) || (g == CS_GRP_IRET);
}


int
is_cs_call_MIPS_ins(cs_insn *ins)
{
	uint64_t t;
  	cs_mips_op *mipsop; 
  	callInfo callInfoStruct;
  	char const *err;
	switch(ins->id) 
	{
		case MIPS_INS_JAL:
			for(int k = 0; k < ins->detail->mips.op_count; k++) 
			{
		 		 mipsop = &ins->detail->mips.operands[k];
		  		 if(mipsop->type == MIPS_OP_IMM) 
				 {
		   			 t = mipsop->imm; 
					 //printf("bal==1  immediate 0x%jx    %s   %s    t=0x%jx \n", ins->address,ins->mnemonic,ins->op_str,t);
					 callInfoStruct.callAddLoc    = ins->address;
					 callInfoStruct.callAddTarget = t;
					 callTargets.insert(callInfoStruct);
				 }
			}
			return 1;
			break;
		case MIPS_INS_JALR:
			for(int k = 0; k < ins->detail->mips.op_count; k++) 
			{
		 		 mipsop = &ins->detail->mips.operands[k];
		  		 if(mipsop->type == MIPS_OP_IMM) 
				 {
		   			 t = mipsop->imm; 
					 //printf("bal==1  immediate 0x%jx    %s   %s    t=0x%jx \n", ins->address,ins->mnemonic,ins->op_str,t);
					 callInfoStruct.callAddLoc    = ins->address;
					 callInfoStruct.callAddTarget = t;
					 callTargets.insert(callInfoStruct);
				 }
			}
			return 1;
			break;
	}  
	return 0;      
}

int
is_cs_cflow_ins(cs_insn *ins, int archi)
{
  size_t i;

  for(i = 0; i < ins->detail->groups_count; i++) 
  {
    if(is_cs_cflow_group(ins->detail->groups[i])) 
    {  //returns true for jmp/call/ret insts
      return 1;
    }
  }
  
  //is_cs_cflow_group does not return true for mips call instructions
  if (archi==5 && is_cs_call_MIPS_ins(ins))
  	return 1;
  return 0;
}

//original
/*int
is_cs_call_ins(cs_insn *ins)
{
  switch(ins->id) {
  case X86_INS_CALL:
  case X86_INS_LCALL:
    return 1;
  default:
    return 0;
  }
}*/

int
is_cs_call_X86_ins(cs_insn *ins)
{
  char const *err;
  switch(ins->id) 
  {
	case X86_INS_CALL:
	case X86_INS_LCALL:
		return 1;
	default:
		return 0;
  }
}

int
is_cs_call_ARM_ins(cs_insn *ins)
{
  uint64_t t;
  cs_arm_op *armop; 
  callInfo callInfoStruct;
  char const *err;
  switch(ins->id) 
  {
	case ARM_INS_BL:
		for(int k = 0; k < ins->detail->arm.op_count; k++) 
		{
         		 armop = &ins->detail->arm.operands[k];
          		 if(armop->type == ARM_OP_IMM) 
			 {
           			 t = armop->imm; 
				 //printf("bal==1  immediate 0x%jx    %s   %s    t=0x%jx \n", ins->address,ins->mnemonic,ins->op_str,t);
				 callInfoStruct.callAddLoc    = ins->address;
				 callInfoStruct.callAddTarget = t;
				 callTargets.insert(callInfoStruct);
			 }
		}
		return 1;
		break;
	case ARM_INS_BLX:
		for(int k = 0; k < ins->detail->arm.op_count; k++) 
		{
         		 armop = &ins->detail->arm.operands[k];
          		 if(armop->type == ARM_OP_IMM) 
			 {
           			 t = armop->imm; 
				 //printf("bal==1  immediate 0x%jx    %s   %s    t=0x%jx \n", ins->address,ins->mnemonic,ins->op_str,t);
				 callInfoStruct.callAddLoc    = ins->address;
				 callInfoStruct.callAddTarget = t;
				 callTargets.insert(callInfoStruct);
			 }
		}
		return 1;
		break;
  	default:
		return 0;
  }
}


int printInstDetailsAndTargets(std::vector<section_map_t> *smaps, char **InstDetailTxt)
{
	std::map<uint64_t, InstrInfo>::iterator it; 
	FILE * fp;
   	int i =0;
	section_map_t *s;
   	/* open the file for writing*/
	fp = fopen (*InstDetailTxt,"w");	

	for (it = InstrInfoMaps.begin(); it != InstrInfoMaps.end(); it++)
	{
		s = section_map_by_addr(smaps, it->first);
		if (s->name==".text")
		{
			fprintf (fp, "0x%jx --- %s --- %s --- %d --- %d\n", it->first, InstrInfoMaps[it->first].opcode, InstrInfoMaps[it->first].operands, InstrInfoMaps[it->first].isCond, InstrInfoMaps[it->first].targetSet.size());
			for (auto tgtIt=InstrInfoMaps[it->first].targetSet.begin(); tgtIt!= InstrInfoMaps[it->first].targetSet.end(); ++tgtIt) 
			{
				fprintf (fp, "Target:0x%jx\n", *tgtIt);
				//printf ("Target:0x%jx \n", *tgtIt);
				//fprintf (fp, "Target:0x%jx \n", *tgtIt);
			}				
			//fprintf("Targets:0x%jx  \n",*tgtIt);
			//for (auto it=InstrInfoMaps[ins->address-4].targetSet.begin(); it != InstrInfoMaps[ins->address-4].targetSet.end(); ++it) 
				//printf("targets..0x%jx  \n",*it);
			//print the target addresses
			//fprintf (fp, "0x%jx	%s	%s	%d	%s\n", it->first, it->second.opcode,it->second.operands,it->second.isCond,it->second.isCond);	
			//printf("****end ins->address..0x%jx  %s  %s  %d %s\n",ins->address,InstrInfoMaps[ins->address].opcode,InstrInfoMaps[ins->address].operands,InstrInfoMaps[ins->address].isCond,InstrInfoMaps[ins->address].targetSet);
		}
	}

	//char *opcode;
        //char *operands;
        //int  isCond;
        //std::set<uint64_t> targetSet;  

}

int 
is_cs_BAL_MIPS_ins(cs_insn *ins)
{
	switch(ins->id) 
	{
		case MIPS_INS_BAL:
			return 1;
		default:
			return 0;
  	}
}

//https://docs.rs/capstone-sys/0.8.0/src/capstone_sys/home/cratesfyi/cratesfyi/debug/build/capstone-sys-c1ea858a1f6cf59d/out/capstone.rs.html?search=MIPS_INS_SLT
/*int is_cs_SLTIU_MIPS_ins(cs_insn *ins)
{
  	uint64_t t=-1;
  	cs_mips_op *mipsop; 
  	callInfo callInfoStruct;
  	char const *err;
	switch(ins->id)
	{
		case MIPS_INS_SLTIU:
		{
			for(int k = 0; k < ins->detail->mips.op_count; k++) 
			{
		 		 mipsop = &ins->detail->mips.operands[k];
		  		 if(mipsop->type == MIPS_OP_IMM) 
				 {
		   			 t = mipsop->imm; 
					 printf("MIPS_INS_SLTIU  immediate 0x%jx    %s   %s    t=0x%jx \n", ins->address,ins->mnemonic,ins->op_str,t);
					 callInfoStruct.callAddLoc    = ins->address;
					 callInfoStruct.callAddTarget = t;
					 callTargets.insert(callInfoStruct);
				 }
				 else
				 {
					printf("MIPS ins->op_str %s  armop->type %s   \n",ins->op_str, mipsop->type);
                                 }

                                 
			}
			return t;
		}
		default:
			return -1;
	}
}*/
std::set<uint64_t>
readROData(elf_data_t *elf, std::vector<section_map_t> *smaps, uint64_t addr, char const **err, uint64_t size)
{
  uint8_t code[CODE_CHUNK_SIZE];
  uint64_t roDataAdd =0;
  int ret=0;
  size_t len=size;
  int count=0;
  std::set<uint64_t> targetSet;
  //printf("here1...\n");
  if(read_elf_section_by_addr(elf, smaps, addr, code, &len, err) < 0) 
  {
      goto fail;
  }
  //printf("here2...\n");
  //for(int topRODataAdd = (addr+3); topRODataAdd <(addr+size); topRODataAdd++)
  for(int topRODataAdd = 3; topRODataAdd <size; topRODataAdd=topRODataAdd+4)
  {
	count = count + 1;
	//printf("here3...\n");
	//printf("topRODataAdd::0x%jx  topRODataAdd::%d  data::0x%jx  data::%d\n",topRODataAdd,topRODataAdd,code[topRODataAdd],code[topRODataAdd]);
        //printf("topRODataAdd::0x%jx  topRODataAdd::%d  data::0x%jx  data::%d\n",topRODataAdd-1,topRODataAdd-1,code[topRODataAdd-1],code[topRODataAdd-1]);
	//printf("topRODataAdd::0x%jx  topRODataAdd::%d  data::0x%jx  data::%d\n",topRODataAdd-2,topRODataAdd-2,code[topRODataAdd-2],code[topRODataAdd-2]);
        //printf("topRODataAdd::0x%jx  topRODataAdd::%d  data::0x%jx  data::%d\n",topRODataAdd-3,topRODataAdd-3,code[topRODataAdd-3],code[topRODataAdd-3]);
	//printf("roDataAdd::0x%jx    roDataAdd::%d    roData::0x%jx\n", topRODataAdd,topRODataAdd);
	roDataAdd = code[topRODataAdd]*256*256*256 + code[topRODataAdd-1]*256*256 + code[topRODataAdd-2]*256 + code[topRODataAdd-3];
        //printf("here4...\n");
	//printf("roDataAdd::0x%jx    roData::0x%jx\n", topRODataAdd-3,roDataAdd);
	//we will check if the read addresses are in the text section

	if (roDataAdd>=sectionStartsAdd[".text"] && roDataAdd<=sectionEndsAdd[".text"])
	{
		targetSet.insert(roDataAdd); 	
		//printf("int text::count::%d  roDataAdd::0x%jx    roData::0x%jx\n",count, addr+topRODataAdd-3,roDataAdd);
	}
	//printf("count::%d  roDataAdd::0x%jx    roData::0x%jx\n",count, addr+topRODataAdd-3,roDataAdd);
  }
  //printf("here5...\n");
fail:
  ret = -1;

cleanup:
  return targetSet;

}
std::set<uint64_t>
is_cs_SLTIU_MIPS_ins(cs_insn *ins,int archi,elf_data_t *elf,std::vector<section_map_t> *smaps,char const **err)
{
	uint64_t t=-1;
  	cs_mips_op *mipsop; 
  	callInfo callInfoStruct;
	int reg=-1;
	std::set<uint64_t> targetSet;

	switch(ins->id) 
	{
		case MIPS_INS_SLTIU:
			{
			std::map<int,int>::iterator it1 = mipsSwitchJumpsAfterThisBlk.find(1);
			std::map<int,int>::iterator it2 = mipsSwitchJumpsAfterThisBlk.find(2);
			std::map<int,int>::iterator it3 = mipsSwitchJumpsAfterThisBlk.find(3);
			//if (ins->address==4262408 ||ins->address==4268028)
			//	printf("\n1.MIPS_INS_SLTIU 0x%jx    %s   %s ", ins->address,ins->mnemonic,ins->op_str);
			/*if(it1 == mipsSwitchJumpsAfterThisBlk.end() && it2 == mipsSwitchJumpsAfterThisBlk.end() && it3 == mipsSwitchJumpsAfterThisBlk.end())
			{
				if (ins->address==4324584)
					printf("\n2.MIPS_INS_SLTIU 0x%jx    %s   %s ", ins->address,ins->mnemonic,ins->op_str);	
				mipsSwitchJumpsAfterThisBlk[1]=ins->address;
			}*/
			if(mipsSwitchJumpsAfterThisBlk[1]==0 && mipsSwitchJumpsAfterThisBlk[2]==0 && mipsSwitchJumpsAfterThisBlk[3]==0 && mipsSwitchJumpsAfterThisBlk[4] == 0 && mipsSwitchJumpsAfterThisBlk[5] == 0)
			{
				//if (ins->address==4262408 ||ins->address==4268028)
				//	printf("\n2.MIPS_INS_SLTIU 0x%jx    %s   %s ", ins->address,ins->mnemonic,ins->op_str);	
				mipsSwitchJumpsAfterThisBlk[1]=ins->address;
				for(int k = 0; k < ins->detail->mips.op_count; k++) 
				{
			 		 mipsop = &ins->detail->mips.operands[k];
			  		 if(mipsop->type == MIPS_OP_IMM) 
					 {
			   			 t = mipsop->imm; 
						 //printf("is_cs_SLTIU_MIPS_ins  immediate 0x%jx    %s   %s    t=0x%jx  t=%d\n", ins->address,ins->mnemonic,ins->op_str,t,t);
						 sltiuSwitchCaseNo = t;
						 //return -1;
					 }
				}
			}
			else
			{	
				//printf("\n2ELSE MIPS_INS_SLTIU mipsSwitchJumpsAfterThisBlk[1]::%jx",mipsSwitchJumpsAfterThisBlk[1]);
				//printf("\n2ELSE MIPS_INS_SLTIU mipsSwitchJumpsAfterThisBlk[2]::%jx",mipsSwitchJumpsAfterThisBlk[2]);
				//printf("\n2ELSE MIPS_INS_SLTIU mipsSwitchJumpsAfterThisBlk[3]::%jx",mipsSwitchJumpsAfterThisBlk[3]);
				//printf("\n2ELSE MIPS_INS_SLTIU mipsSwitchJumpsAfterThisBlk[4]::%jx",mipsSwitchJumpsAfterThisBlk[4]);
				//printf("\n2ELSE MIPS_INS_SLTIU mipsSwitchJumpsAfterThisBlk[5]::%jx",mipsSwitchJumpsAfterThisBlk[5]);
				mipsSwitchJumpsAfterThisBlk.clear();
			}

			}
			break;
		case MIPS_INS_BEQZ:
			{
			//check if key1 is alr in the map and 2 and 3 are not in the map
			std::map<int,int>::iterator it1 = mipsSwitchJumpsAfterThisBlk.find(1);
			std::map<int,int>::iterator it2 = mipsSwitchJumpsAfterThisBlk.find(2);
			std::map<int,int>::iterator it3 = mipsSwitchJumpsAfterThisBlk.find(3);
			//if (ins->address==4262412 ||ins->address==4268040)
			//	printf("\n1.MIPS_INS_BEQZ 0x%jx    %s   %s ", ins->address,ins->mnemonic,ins->op_str);
			/*if(it1 != mipsSwitchJumpsAfterThisBlk.end() && it2 == mipsSwitchJumpsAfterThisBlk.end() && it3 == mipsSwitchJumpsAfterThisBlk.end())
			{
				if (ins->address==4324588)
					printf("\n2.MIPS_INS_BEQZ 0x%jx    %s   %s ", ins->address,ins->mnemonic,ins->op_str);		
				mipsSwitchJumpsAfterThisBlk[2]=ins->address;
			}*/
			if(mipsSwitchJumpsAfterThisBlk[1]!=0 && mipsSwitchJumpsAfterThisBlk[2]==0 && mipsSwitchJumpsAfterThisBlk[3]==0 && mipsSwitchJumpsAfterThisBlk[4] == 0 && mipsSwitchJumpsAfterThisBlk[5] == 0)
			{
				//if (ins->address==4262412 ||ins->address==4268040)
				//	printf("\n2.MIPS_INS_BEQZ 0x%jx    %s   %s ", ins->address,ins->mnemonic,ins->op_str);		
				mipsSwitchJumpsAfterThisBlk[2]=ins->address;
			}
			else
			{	
				//printf("\n2ELSE MIPS_INS_BEQZ mipsSwitchJumpsAfterThisBlk[1]::%jx",mipsSwitchJumpsAfterThisBlk[1]);
				//printf("\n2ELSE MIPS_INS_BEQZ mipsSwitchJumpsAfterThisBlk[2]::%jx",mipsSwitchJumpsAfterThisBlk[2]);
				//printf("\n2ELSE MIPS_INS_BEQZ mipsSwitchJumpsAfterThisBlk[3]::%jx",mipsSwitchJumpsAfterThisBlk[3]);
				//printf("\n2ELSE MIPS_INS_BEQZ mipsSwitchJumpsAfterThisBlk[4]::%jx",mipsSwitchJumpsAfterThisBlk[4]);
				//printf("\n2ELSE MIPS_INS_BEQZ mipsSwitchJumpsAfterThisBlk[5]::%jx",mipsSwitchJumpsAfterThisBlk[5]);
				mipsSwitchJumpsAfterThisBlk.clear();
			}
			}
			break;
		case MIPS_INS_SLL:
			{
			//check if mipsSwitchJumpsAfterThisBlk contains key 1 and 2
			std::map<int,int>::iterator it1 = mipsSwitchJumpsAfterThisBlk.find(1);
			std::map<int,int>::iterator it2 = mipsSwitchJumpsAfterThisBlk.find(2);
			std::map<int,int>::iterator it3 = mipsSwitchJumpsAfterThisBlk.find(3);
			//if (ins->address==4262416 ||ins->address==4268044)
			//	printf("\n1.MIPS_INS_SLL 0x%jx    %s   %s ", ins->address,ins->mnemonic,ins->op_str);
			/*if(it1 != mipsSwitchJumpsAfterThisBlk.end() && it2 != mipsSwitchJumpsAfterThisBlk.end() && it3 == mipsSwitchJumpsAfterThisBlk.end())
			{
				if (ins->address==4324596)
					printf("\n2.MIPS_INS_SLL 0x%jx    %s   %s ", ins->address,ins->mnemonic,ins->op_str);
				mipsSwitchJumpsAfterThisBlk[3]=ins->address;
				if ((mipsSwitchJumpsAfterThisBlk[2] - mipsSwitchJumpsAfterThisBlk[1])<=20 && (mipsSwitchJumpsAfterThisBlk[2] - mipsSwitchJumpsAfterThisBlk[1])>=0 && (mipsSwitchJumpsAfterThisBlk[3] - mipsSwitchJumpsAfterThisBlk[2])<=20 && (mipsSwitchJumpsAfterThisBlk[3] - mipsSwitchJumpsAfterThisBlk[2])>=0)
				{
					//printf("\nMIPS_INS_SLL 0x%jx    %s   %s ", ins->address,ins->mnemonic,ins->op_str);
					//printf("\nmipsSwitchJumpsAfterThisBlk[1]::%jx",mipsSwitchJumpsAfterThisBlk[1]);
					//printf("\nmipsSwitchJumpsAfterThisBlk[2]::%jx",mipsSwitchJumpsAfterThisBlk[2]);
					//printf("\nmipsSwitchJumpsAfterThisBlk[3]::%jx",mipsSwitchJumpsAfterThisBlk[3]);
					//mipsSwitchJumpsAfterThisBlk.erase(1); 
					//mipsSwitchJumpsAfterThisBlk.erase(2);  
					//mipsSwitchJumpsAfterThisBlk.erase(3);  
				}
			}*/
			if(mipsSwitchJumpsAfterThisBlk[1]!=0 && mipsSwitchJumpsAfterThisBlk[2]!=0 && mipsSwitchJumpsAfterThisBlk[3]==0 && mipsSwitchJumpsAfterThisBlk[4] == 0 && mipsSwitchJumpsAfterThisBlk[5] == 0)
			{
				//if (ins->address==4262416 ||ins->address==4268044)
				//	printf("\n2.MIPS_INS_SLL 0x%jx    %s   %s ", ins->address,ins->mnemonic,ins->op_str);
				mipsSwitchJumpsAfterThisBlk[3]=ins->address;
			}
			else
			{
				//printf("\n2ELSE MIPS_INS_SLL mipsSwitchJumpsAfterThisBlk[1]::%jx",mipsSwitchJumpsAfterThisBlk[1]);
				//printf("\n2ELSE MIPS_INS_SLL mipsSwitchJumpsAfterThisBlk[2]::%jx",mipsSwitchJumpsAfterThisBlk[2]);
				//printf("\n2ELSE MIPS_INS_SLL mipsSwitchJumpsAfterThisBlk[3]::%jx",mipsSwitchJumpsAfterThisBlk[3]);
				//printf("\n2ELSE MIPS_INS_SLL mipsSwitchJumpsAfterThisBlk[4]::%jx",mipsSwitchJumpsAfterThisBlk[4]);
				//printf("\n2ELSE MIPS_INS_SLL mipsSwitchJumpsAfterThisBlk[5]::%jx",mipsSwitchJumpsAfterThisBlk[5]);
			}
			}
			break;
		case MIPS_INS_LW:
			{
			std::map<int,int>::iterator it1 = mipsSwitchJumpsAfterThisBlk.find(1);
			std::map<int,int>::iterator it2 = mipsSwitchJumpsAfterThisBlk.find(2);
			std::map<int,int>::iterator it3 = mipsSwitchJumpsAfterThisBlk.find(3);
			std::map<int,int>::iterator it4 = mipsSwitchJumpsAfterThisBlk.find(4);
			std::map<int,int>::iterator it5 = mipsSwitchJumpsAfterThisBlk.find(5);
			//if (ins->address==4262424 || ins->address==4268064)
			//	printf("\n1.MIPS_INS_LW 0x%jx    %s   %s ", ins->address,ins->mnemonic,ins->op_str);
			/*if(it1 != mipsSwitchJumpsAfterThisBlk.end() && it2 != mipsSwitchJumpsAfterThisBlk.end() && it3 != mipsSwitchJumpsAfterThisBlk.end() && it4 == mipsSwitchJumpsAfterThisBlk.end() && it5 == mipsSwitchJumpsAfterThisBlk.end())
			{
				if (ins->address==4324612)
					printf("\n2.MIPS_INS_LW 0x%jx    %s   %s ", ins->address,ins->mnemonic,ins->op_str);	
				mipsSwitchJumpsAfterThisBlk[4]=ins->address;
			}*/
			if(mipsSwitchJumpsAfterThisBlk[1]!=0 && mipsSwitchJumpsAfterThisBlk[2]!=0 && mipsSwitchJumpsAfterThisBlk[3]!=0 && mipsSwitchJumpsAfterThisBlk[4] == 0 && mipsSwitchJumpsAfterThisBlk[5] == 0)
			{
				//if (ins->address==4262424 || ins->address==4268064)
				//	printf("\n2.MIPS_INS_LW 0x%jx    %s   %s ", ins->address,ins->mnemonic,ins->op_str);	
				mipsSwitchJumpsAfterThisBlk[4]=ins->address;
			}
			else
			{
				//printf("\n2ELSE MIPS_INS_LW mipsSwitchJumpsAfterThisBlk[1]::%jx",mipsSwitchJumpsAfterThisBlk[1]);
				//printf("\n2ELSE MIPS_INS_LW mipsSwitchJumpsAfterThisBlk[2]::%jx",mipsSwitchJumpsAfterThisBlk[2]);
				//printf("\n2ELSE MIPS_INS_LW mipsSwitchJumpsAfterThisBlk[3]::%jx",mipsSwitchJumpsAfterThisBlk[3]);
				//printf("\n2ELSE MIPS_INS_LW mipsSwitchJumpsAfterThisBlk[4]::%jx",mipsSwitchJumpsAfterThisBlk[4]);
				//printf("\n2ELSE MIPS_INS_LW mipsSwitchJumpsAfterThisBlk[5]::%jx",mipsSwitchJumpsAfterThisBlk[5]);

			}
			if ((mipsSwitchJumpsAfterThisBlk[2] - mipsSwitchJumpsAfterThisBlk[1])<=20 && (mipsSwitchJumpsAfterThisBlk[2] - mipsSwitchJumpsAfterThisBlk[1])>=0 && (mipsSwitchJumpsAfterThisBlk[3] - mipsSwitchJumpsAfterThisBlk[2])<=20 && (mipsSwitchJumpsAfterThisBlk[3] - mipsSwitchJumpsAfterThisBlk[2])>=0 && (mipsSwitchJumpsAfterThisBlk[4] - mipsSwitchJumpsAfterThisBlk[3])<=30 && (mipsSwitchJumpsAfterThisBlk[4] - mipsSwitchJumpsAfterThisBlk[3])>=0)
			{ //do nothing
			}
			else
			{
				mipsSwitchJumpsAfterThisBlk.clear();
			}

			}
			break;
		case MIPS_INS_JR:
			{
				std::map<int,int>::iterator it1 = mipsSwitchJumpsAfterThisBlk.find(1);
				std::map<int,int>::iterator it2 = mipsSwitchJumpsAfterThisBlk.find(2);
				std::map<int,int>::iterator it3 = mipsSwitchJumpsAfterThisBlk.find(3);
				std::map<int,int>::iterator it4 = mipsSwitchJumpsAfterThisBlk.find(4);
				std::map<int,int>::iterator it5 = mipsSwitchJumpsAfterThisBlk.find(5);
				//if (ins->address==4262428 || ins->address==4268068)
				//	printf("\n1.MIPS_INS_JR 0x%jx    %s   %s ", ins->address,ins->mnemonic,ins->op_str);
				/*if(it1 != mipsSwitchJumpsAfterThisBlk.end() && it2 != mipsSwitchJumpsAfterThisBlk.end() && it3 != mipsSwitchJumpsAfterThisBlk.end() && it4 != mipsSwitchJumpsAfterThisBlk.end() && it5 == mipsSwitchJumpsAfterThisBlk.end())
				{
					if (ins->address==4324616)
						printf("\n2.MIPS_INS_JR 0x%jx    %s   %s ", ins->address,ins->mnemonic,ins->op_str);
					if (ins->address - mipsSwitchJumpsAfterThisBlk[4] == 4 && roDataToReadSwitchCases!=-1)
					{
					printf("\nMIPS_INS_SLL 0x%jx ", ins->address,ins->mnemonic,ins->op_str);
					printf("\nmipsSwitchJumpsAfterThisBlk[1]::%jx",mipsSwitchJumpsAfterThisBlk[1]);
					printf("\nmipsSwitchJumpsAfterThisBlk[2]::%jx",mipsSwitchJumpsAfterThisBlk[2]);
					printf("\nmipsSwitchJumpsAfterThisBlk[3]::%jx",mipsSwitchJumpsAfterThisBlk[3]);
					printf("\nroDataToReadSwitchCases::%jx",roDataToReadSwitchCases);
					switchCasesSllTargets.insert(mipsSwitchJumpsAfterThisBlk[3]);
					mipsSwitchJumpsAfterThisBlk.clear();
					printf("**************\n");
					for (std::set<uint64_t>::iterator it=switchCasesSllTargets.begin(); it!=switchCasesSllTargets.end(); ++it)
					{	printf("switchCasesSllTargets:: %jx  \n", *it);
					}
    					printf("**************\n");

					}
				}*/
				if(mipsSwitchJumpsAfterThisBlk[1]!=0 && mipsSwitchJumpsAfterThisBlk[2]!=0 && mipsSwitchJumpsAfterThisBlk[3]!=0 && mipsSwitchJumpsAfterThisBlk[4] != 0 && mipsSwitchJumpsAfterThisBlk[5] == 0)
				{
					//this is a jr instruction and if it has switch jump targets, we will find it in the targetSet set 
					if (ins->address - mipsSwitchJumpsAfterThisBlk[4] == 4 && roDataToReadSwitchCases!=-1)
					{
						switchCasesSllTargets.insert(mipsSwitchJumpsAfterThisBlk[3]);
						//printf("**************\n");
						//printf("switchCasesSllTargets inst:: %jx  rodataaddr:: %jx  noSwitch::%d \n", mipsSwitchJumpsAfterThisBlk[3],roDataToReadSwitchCases,sltiuSwitchCaseNo);

						if (roDataToReadSwitchCases>=sectionStartsAdd[".rodata"] && roDataToReadSwitchCases<=sectionEndsAdd[".rodata"])
						{
							targetSet = readROData(elf, smaps, roDataToReadSwitchCases, err, sltiuSwitchCaseNo*4);
							//for (std::set<uint64_t>::iterator it=targetSet.begin(); it!=targetSet.end(); ++it)
							//	printf("\ntargetSet:: %jx size:%d", *it,targetSet.size());
						}

	    					//printf("**************\n");
						mipsSwitchJumpsAfterThisBlk.clear();
					}
					else
					{
						//printf("ELSE ins->address - mipsSwitchJumpsAfterThisBlk[4]:: %d ins->address::%d mipsSwitchJumpsAfterThisBlk[4]::%d roDataToReadSwitchCases::%d \n",(ins->address - mipsSwitchJumpsAfterThisBlk[4]),ins->address,mipsSwitchJumpsAfterThisBlk[4],roDataToReadSwitchCases);
					}
				}
				/*else
				{
					//printf("\n2ELSE MIPS_INS_JR mipsSwitchJumpsAfterThisBlk[1]::%jx",mipsSwitchJumpsAfterThisBlk[1]);
					//printf("\n2ELSE MIPS_INS_JR mipsSwitchJumpsAfterThisBlk[2]::%jx",mipsSwitchJumpsAfterThisBlk[2]);
					//printf("\n2ELSE MIPS_INS_JR mipsSwitchJumpsAfterThisBlk[3]::%jx",mipsSwitchJumpsAfterThisBlk[3]);
					//printf("\n2ELSE MIPS_INS_JR mipsSwitchJumpsAfterThisBlk[4]::%jx",mipsSwitchJumpsAfterThisBlk[4]);
					//printf("\n2ELSE MIPS_INS_JR mipsSwitchJumpsAfterThisBlk[5]::%jx",mipsSwitchJumpsAfterThisBlk[5]);
				}*/
			}
		case MIPS_INS_LUI:
			for(int k = 0; k < ins->detail->mips.op_count; k++) //lui $v0,0x44
			{
		 		 mipsop = &ins->detail->mips.operands[k];
		  		 if(mipsop->type == MIPS_OP_IMM) 
				 {
		   			 t = mipsop->imm; 
					 //printf("MIPS_INS_LUI  immediate 0x%jx    %s   %s    t=0x%jx  t=%d\n", ins->address,ins->mnemonic,ins->op_str,t,t);
					 if (reg!=-1)
					 {
						jmpsAfterroDataToReadSwitchCases =0;	
						luiRegMapForMIPS[reg] = t;
					 }
					 //return -1;
				 }
				 if(mipsop->type == MIPS_OP_REG) 
            			 {
					if (reg==-1)
						reg = mipsop->reg-66; 
				 }
			}
			break;
		case MIPS_INS_ADDIU:
			for(int k = 0; k < ins->detail->mips.op_count; k++) 
			{
		 		 mipsop = &ins->detail->mips.operands[k];
		  		 if(mipsop->type == MIPS_OP_IMM) 
				 {
		   			 t = mipsop->imm; 
					 //printf("MIPS_INS_ADDIU  immediate 0x%jx    %s   %s    t=0x%jx  t=%d\n", ins->address,ins->mnemonic,ins->op_str,t,t);
					 if (reg!=-1)
					 {
						std::map<int,int>::iterator it = luiRegMapForMIPS.find(reg);
						if(it != luiRegMapForMIPS.end())
						{
							addiuRegMapForMIPS[reg] = it->second*16*16*16*16 + t; //this is the rodata address that contains all the switch table addresses
							roDataToReadSwitchCases = addiuRegMapForMIPS[reg];
							/*if(ins->address ==4268056 || ins->address ==4262356 ||ins->address ==4324604 )
								printf("MIPS_INS_LUI  immediate 0x%jx    %s   %s    t=0x%jx  t=%d addiuRegMapForMIPS[reg]=0x%jx\n sltiuSwitchCaseNo=%d", ins->address,ins->mnemonic,ins->op_str,t,t,addiuRegMapForMIPS[reg],sltiuSwitchCaseNo);*/
						
						}
					 }
					 //return -1;
				 }
				 if(mipsop->type == MIPS_OP_REG) 
            			 {
					if (reg==-1)
						reg = mipsop->reg-66; 
				 }
			}
			break;
	} 
	//after the redatatoread is calculated, at max we can have one beqz statement...the fallthrough blk is attached to all the switch stmts
	if (roDataToReadSwitchCases!=-1)
	{	
		if(is_cs_cflow_ins(ins,archi)==1 && ins->id!=MIPS_INS_BEQZ)
		{
			//printf("CFLOW RESET1:: inst add:: 0x%jx %s %s roDataToReadSwitchCases::%d  %jx\n", ins->address,ins->mnemonic,ins->op_str,roDataToReadSwitchCases,roDataToReadSwitchCases);
			roDataToReadSwitchCases=-1; //reseting the switch case data add	
		}
		else if (is_cs_cflow_ins(ins,archi)==1 && ins->id==MIPS_INS_BEQZ)
		{
			jmpsAfterroDataToReadSwitchCases = jmpsAfterroDataToReadSwitchCases +1;
			if(jmpsAfterroDataToReadSwitchCases>1)
			{
				//printf("CFLOW RESET2:: inst add:: 0x%jx %s %s roDataToReadSwitchCases::%d  %jx  jmpsAfterroDataToReadSwitchCases:: %d\n", ins->address,ins->mnemonic,ins->op_str,roDataToReadSwitchCases,roDataToReadSwitchCases,jmpsAfterroDataToReadSwitchCases);
				roDataToReadSwitchCases=-1;
			}
			else
			{
				//printf("CFLOW 1:: inst add:: 0x%jx %s %s roDataToReadSwitchCases::%d  %jx  jmpsAfterroDataToReadSwitchCases:: %d\n", ins->address,ins->mnemonic,ins->op_str,roDataToReadSwitchCases,roDataToReadSwitchCases,jmpsAfterroDataToReadSwitchCases);
			}	
		}
	} 
	return targetSet;      
}

int 
addBBForBALInst_MIPS_ins(std::vector<section_map_t> *smaps)
{
	//1. sort the func starts vector
	sort(globalFuncStartsVect.begin(), globalFuncStartsVect.end()); 
	//2.iterate through the bal structures
	std::set<balInfo>::iterator it1;
	std::vector<uint64_t>::iterator currFunc;
	std::vector<uint64_t>::iterator prevFunc;
	printf("balTargets end size :: %d  \n", balTargets.size());
	for (it1 =balTargets.begin(); it1 != balTargets.end(); ++it1)
	{
		for(currFunc=globalFuncStartsVect.begin(); currFunc!= globalFuncStartsVect.end(); ++currFunc) 
		{
			if(it1->balAddLoc<*currFunc)
			{
				break;		  
		        }
			prevFunc = currFunc;
		}
		//3.check if the bal inst address and the bal target location is both withing the same func
		if((it1->balAddLoc>*prevFunc && it1->balAddLoc<*currFunc && it1->balAddTarget>*prevFunc  &&  it1->balAddTarget<*currFunc) 
			||(*currFunc ==0  && it1->balAddLoc>*prevFunc && it1->balAddTarget>*prevFunc))//second cond is for the last func
		{
			//4. we need to create the BBs
			btype_t *updateBBb;
			updateBBb = btype_by_addr(smaps, it1->balAddTarget);
			if(!updateBBb) 
			{
				//printf("2returned 0 =(\n");
				return 0;
			}
			updateBBb->bbstart = MAP_FLAG_T;
			updateBBb = btype_by_addr(smaps,it1->balAddLoc + 4);
			if(!updateBBb) 
			{
				//printf("3returned 0 =(\n");
				return 0;
			}
			updateBBb->bbstart = MAP_FLAG_T;
			
			//we should update the CFG details as well
			InstrInfoMaps[it1->balAddLoc].targetSet.insert(it1->balAddTarget); //connecting bal inst to target
			InstrInfoMaps[it1->balAddLoc].targetSet.insert(it1->balAddLoc+4); //connecting the bal inst to following nop
			InstrInfoMaps[it1->balAddLoc+4].targetSet.insert(it1->balAddLoc+8); //connecting the nop inst to the following inst
			//printf("bal inst tgt in function :: 0x%jx ", it1->balAddLoc);
		}
		//4.else bal inst is calling a new function
		else
		{
			callInfo callInfoStruct;
			callInfoStruct.callAddLoc    = it1->balAddLoc;
			callInfoStruct.callAddTarget = it1->balAddTarget;
			callTargets.insert(callInfoStruct);
		}
	}
	return 1; 
}


int 
addFuncCallForInst_ARM_ins(std::vector<section_map_t> *smaps)
{

	//1. sort the func starts vector
	sort(globalFuncStartsVect.begin(), globalFuncStartsVect.end()); 
	//2.iterate through the bal structures
	std::set<balInfo>::iterator it1;
	std::vector<uint64_t>::iterator currFunc;
	std::vector<uint64_t>::iterator prevFunc;
	printf("balTargets end size :: %d  \n", balTargets.size());
	for (it1 =balTargets.begin(); it1 != balTargets.end(); ++it1)
	{
		for(currFunc=globalFuncStartsVect.begin(); currFunc!= globalFuncStartsVect.end(); ++currFunc) 
		{
			if(it1->balAddLoc<*currFunc)
			{
				break;		  
		        }
			prevFunc = currFunc;
		}
		//3.check if the bal inst address and the bal target location is both withing the same func
		if((it1->balAddLoc>*prevFunc && it1->balAddLoc<*currFunc && it1->balAddTarget>*prevFunc  &&  it1->balAddTarget<*currFunc) 
			||(*currFunc ==0  && it1->balAddLoc>*prevFunc && it1->balAddTarget>*prevFunc))//second cond is for the last func
		{
			//4. we need to create the BBs
			btype_t *updateBBb;
			updateBBb = btype_by_addr(smaps, it1->balAddTarget);
			if(!updateBBb) 
			{
				printf("2returned 0 =(\n");
				return 0;
			}
			updateBBb->bbstart = MAP_FLAG_T;
			updateBBb = btype_by_addr(smaps,it1->balAddLoc + 4);
			if(!updateBBb) 
			{
				printf("3returned 0 =(\n");
				return 0;
			}
			updateBBb->bbstart = MAP_FLAG_T;
		}
	}
	return 1;  
}

int
is_cs_ret_X86_ins(cs_insn *ins)
{
	switch(ins->id) 
	{
		case X86_INS_RET:
		case X86_INS_RETF:
			return 1;
		default:
			return 0;
  	}
}

int
is_cs_ret_ARM_ins(cs_insn *ins)
{
	return 0;
}

int
is_cs_ret_MIPS_ins(cs_insn *ins)
{
	return 0;
}


//original
/*int
is_cs_unconditional_jmp_ins(cs_insn *ins)
{
  switch(ins->id) {
  case X86_INS_JMP:
    return 1;
  default:
    return 0;
  }
}*/

int
is_cs_unconditional_jmp_X86_ins(cs_insn *ins)
{
  switch(ins->id) 
  {
  case X86_INS_JMP:
    return 1;
  default:
    return 0;
  }
}


int
is_cs_unconditional_jmp_ARM_ins(cs_insn *ins)
{
  uint64_t t;
  cs_arm_op *armop; 
  bInfo bInstInfo;
  /*char *opStr = {ins->op_str};
  //handle the pop{cond} which is the return. If condition is not satisfied, control falls to the following block
  if(strcmp(ins->mnemonic, "popeq")==0 || strcmp(ins->mnemonic, "popne")==0 || strcmp(ins->mnemonic, "popgt")==0 || strcmp(ins->mnemonic, "pople")==0    ||
	strcmp(ins->mnemonic, "popcs")==0 || strcmp(ins->mnemonic, "pophs")==0 || strcmp(ins->mnemonic, "popcc")==0 || strcmp(ins->mnemonic, "poplo")==0 ||
	strcmp(ins->mnemonic, "popmi")==0 || strcmp(ins->mnemonic, "poppl")==0 || strcmp(ins->mnemonic, "popal")==0 || strcmp(ins->mnemonic, "popnv")==0 ||
	strcmp(ins->mnemonic, "popvs")==0 || strcmp(ins->mnemonic, "popvc")==0 || strcmp(ins->mnemonic, "pophi")==0 || strcmp(ins->mnemonic, "popls")==0)
  {
	//check for pc in ins->op_str    
        char *result = strstr(opStr, "pc");
        //printf("result::%s\n", result);
        if (result == NULL)
		return 0;
	else
		return 1;
	
  }*/
  switch(ins->id) 
  {
	//ARM
	case ARM_INS_B:
		//printf("bal==1  0x%jx    %s   %s  nop:%d ret:%d jmp:%d cflow:%d call:%d\n", ins->address,ins->mnemonic,ins->op_str ,nop,ret,jmp,cflow,call);
		for(int k = 0; k < ins->detail->arm.op_count; k++) 
		{
         		 armop = &ins->detail->arm.operands[k];
          		 if(armop->type == ARM_OP_IMM) 
			 {
           			 t = armop->imm; 
				 //printf("bal==1  immediate 0x%jx    %s   %s    t=0x%jx \n", ins->address,ins->mnemonic,ins->op_str,t);
				 bInstInfo.bAddLoc = ins->address;
				 bInstInfo.bAddTarget = t;
				 bTargets.insert(bInstInfo);
			 }
		}
		return 1;
		break;
	case ARM_INS_BX:
	case ARM_INS_BXJ:
		return 1;
	default:
		return 0;
  }
}


int 
markBFuncCalls(std::vector<section_map_t> *smaps)
{
	btype_t *updateCall;
	//1. sort the func starts vector
	sort(globalFuncStartsVect.begin(), globalFuncStartsVect.end()); 
	//2. iterate through the b instructions
	std::set<bInfo>::iterator bInstIt;
	std::vector<uint64_t>::iterator funcItr;

	for (bInstIt = bTargets.begin(); bInstIt != bTargets.end(); ++bInstIt)
	{
		if ( std::find(globalFuncStartsVect.begin(), globalFuncStartsVect.end(), bInstIt->bAddTarget) != globalFuncStartsVect.end() )
		{
			updateCall = btype_by_addr(smaps, bInstIt->bAddLoc);
			if(!updateCall) 
			{
				printf("3returned 0 =(\n");
				return 0;
			}
			updateCall->call = MAP_FLAG_T;	
		}				
	}
}

int
is_cs_unconditional_jmp_MIPS_ins(cs_insn *ins)
{
  switch(ins->id) 
  {
	case MIPS_INS_J:
	case MIPS_INS_JR:
	case MIPS_INS_B:
	//case MIPS_INS_BAL: //unconditional branch and link
		return 1;
	default:
		return 0;
  }
}

int
is_cs_conditional_cflow_X86_ins(cs_insn *ins)
{
  /* XXX: it is crucial to use whitelisting here to guarantee correctness */
  switch(ins->id) 
  {
	case X86_INS_JAE:
	case X86_INS_JA:
	case X86_INS_JBE:
	case X86_INS_JB:
	case X86_INS_JCXZ:
	case X86_INS_JECXZ:
	case X86_INS_JE:
	case X86_INS_JGE:
	case X86_INS_JG:
	case X86_INS_JLE:
	case X86_INS_JL:
	case X86_INS_JNE:
	case X86_INS_JNO:
	case X86_INS_JNP:
	case X86_INS_JNS:
	case X86_INS_JO:
	case X86_INS_JP:
	case X86_INS_JRCXZ:
	case X86_INS_JS:
    		return 1;
  	case X86_INS_JMP:
  	default:
    		return 0;
  }
}

int
is_popCond_ARM_ins(cs_insn *ins)
{
  char *opStr = {ins->op_str};
  //handle the pop{cond} which is the return. If condition is not satisfied, control falls to the following block
  if(strcmp(ins->mnemonic, "popeq")==0 || strcmp(ins->mnemonic, "popne")==0 || strcmp(ins->mnemonic, "popgt")==0 || strcmp(ins->mnemonic, "pople")==0    ||
	strcmp(ins->mnemonic, "popcs")==0 || strcmp(ins->mnemonic, "pophs")==0 || strcmp(ins->mnemonic, "popcc")==0 || strcmp(ins->mnemonic, "poplo")==0 ||
	strcmp(ins->mnemonic, "popmi")==0 || strcmp(ins->mnemonic, "poppl")==0 || strcmp(ins->mnemonic, "popal")==0 || strcmp(ins->mnemonic, "popnv")==0 ||
	strcmp(ins->mnemonic, "popvs")==0 || strcmp(ins->mnemonic, "popvc")==0 || strcmp(ins->mnemonic, "pophi")==0 || strcmp(ins->mnemonic, "popls")==0 ||
	strcmp(ins->mnemonic, "popge")==0)
  {
	//check for pc in ins->op_str    
        char *result = strstr(opStr, "pc");
	//printf("is_cs_conditional_cflow_ARM_ins(ins) 0x%jx    %s   %s \n", ins->address,ins->mnemonic,ins->op_str);
        //printf("result::%s\n", result);
        if (result == NULL)
		return 0;
	else
		//printf("result::%s\n", result);
		return 1;	
  }

}

int
is_cs_conditional_cflow_ARM_ins(cs_insn *ins)
{
  /* XXX: we do not whitelist for The file “/home/shaila/Desktop/MyDS/testarmliz01.truth.map” changed on disk.arm since there are many instructions*/
  switch(ins->id) 
  {
	//ARM
	case ARM_INS_B:
	{
		//printf("1.is_cs_conditional_cflow_ARM_ins(ins)==1 0x%jx    %s   %d \n", ins->address,ins->mnemonic,ins->detail->arm.cc);
		if (ins->detail->arm.cc!=15)
		{	
			//printf("1.is_cs_conditional_cflow_ARM_ins(ins)==1 return 1 0x%jx    %s   %d \n", ins->address,ins->mnemonic,ins->detail->arm.cc);
			return 1; 
		}
	}
	case ARM_INS_BX:
	{
		//printf("2.is_cs_conditional_cflow_ARM_ins(ins)==1 0x%jx    %s   %d \n", ins->address,ins->mnemonic,ins->detail->arm.cc);
		if (ins->detail->arm.cc!=15)
		{	
			//printf("2.is_cs_conditional_cflow_ARM_ins(ins)==1 return 1 0x%jx    %s   %d \n", ins->address,ins->mnemonic,ins->detail->arm.cc);
			return 1; 
		}
	}
	case ARM_INS_BXJ:
	{
		//printf("3.is_cs_conditional_cflow_ARM_ins(ins)==1 0x%jx    %s   %d \n", ins->address,ins->mnemonic,ins->detail->arm.cc);
		if (ins->detail->arm.cc!=15)
		{
			//printf("3.is_cs_conditional_cflow_ARM_ins(ins)==1 return 1 0x%jx    %s   %d \n", ins->address,ins->mnemonic,ins->detail->arm.cc);	
			return 1; 
		}
	}	
		return 0; //unconditional jump
	default:
		return 0;
  }
  return 0;
  
}

int
is_cs_conditional_cflow_MIPS_ins(cs_insn *ins)
{
  /* XXX: it is crucial to use whitelisting here to guarantee correctness */
  if(strcmp(ins->mnemonic, "bnezl")==0 || strcmp(ins->mnemonic, "bc1t")==0 ||strcmp(ins->mnemonic, "bc1f")==0 )
	return 1;
  switch(ins->id) {
  //MIPS
  case MIPS_INS_BEQ:
  case MIPS_INS_BEQZ:
  case MIPS_INS_BNE:
  case MIPS_INS_BNEZ:
  case MIPS_INS_BGTZ:
  case MIPS_INS_BLTZ:
  case MIPS_INS_BGEZ:
  case MIPS_INS_BLEZ:
  case MIPS_INS_BNEL:
  case MIPS_INS_BEQL:
    return 1;
  default:
    return 0;
  }
}



int
safe_disasm_linear(elf_data_t *elf, std::vector<section_map_t> *smaps, std::set<uint64_t> *targets,
                   uint64_t addr, uint8_t *code, size_t len, char const **err)
{
  /*
   * Run conservative linear disassembly from the given address. 
   */

  int ret, jmp, init, cflow, call, nop, only_nop, archi,condcflow,armCondInstr=0,bbAfterUncondJump=0,nextRet,nextCall,nextCFlow,nextNop,cflowSaved,bal,mipsSwitchSltiu=-1;
  csh dis;
  cs_mode mode;
  cs_insn *ins,*nextIns;
  section_map_t *sec;
  const uint8_t *pc;
  uint64_t t, pcaddr;
  size_t i, j, d, n, ndisassembled;
  btype_t *b;
  cs_x86_op *op;
  cs_arm_op *armop;   //shaila
  cs_mips_op *mipsop; //shaila
  balInfo balInstInfo;
  uint64_t prevInstAddr=0;
  //mips targetSet for switch
  std::set<uint64_t> switchTargetSet;
  int mipsSwitchTargetsPresent=0;

  init = 0;
  ins  = NULL;

  //shaila:get the archi of the binary
  archi = getMacArchi(elf, err);
  if (archi==1 || archi==2)
  {
	  if(elf->bits == 64) 
	  {
    		mode = CS_MODE_64;
  	  } else 
	  {
    		mode = CS_MODE_32;
  	  }
	  if(cs_open(CS_ARCH_X86, mode, &dis) != CS_ERR_OK) 
	  {
	    (*err) = "failed to initialize libcapstone";
	    goto fail;
	  }
  }
  else if (archi==3 ||archi==4)
  {
    	  mode = CS_MODE_ARM;
	  
          if(elf->bits == 64) 
	  {
		if(cs_open(CS_ARCH_ARM64, mode, &dis) != CS_ERR_OK) 
	        {
	    		(*err) = "failed to initialize libcapstone";
	    		goto fail;
	  	}
  	  } else 
	  {
		if(cs_open(CS_ARCH_ARM, mode, &dis) != CS_ERR_OK) 
	        {
	    		(*err) = "failed to initialize libcapstone";
	    		goto fail;
	  	}
  	  }
	  
  }
  else if (archi==5)
  {
    	  if(elf->bits == 64) 
	  {
    		mode = CS_MODE_MIPS64;
  	  } else 
	  {
    		mode = CS_MODE_MIPS32; //not sure which is better, some issues with both
                //mode = CS_MODE_MIPS32R6; 
  	  }
	  if(cs_open(CS_ARCH_MIPS, mode, &dis) != CS_ERR_OK) 
	  {
	    (*err) = "failed to initialize libcapstone";
	    goto fail;
	  }
  }

  if (archi == -1)
  	print_err("%s", err);
  //shaila:get the archi of the binary
  
  init = 1;
  cs_option(dis, CS_OPT_DETAIL, CS_OPT_ON);
  cs_option(dis, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

  ins = cs_malloc(dis);

  sec = section_map_by_addr(smaps, addr);
  if(!sec) {
    (*err) = "address points outside mapped sections (2)";
    goto fail;
  }
  sec->dismap.insert(addr);

  verbose(2, "disassembling %zu bytes at address 0x%jx (linear)", len, addr);
  pc = code;
  pcaddr = addr;
  n = len;
  d = 0;
  ndisassembled = 0;
  only_nop = 0;
  while(cs_disasm_iter(dis, &pc, &n, &pcaddr, ins)) {
    InstrInfo instInfoStruct;
    //struct InstrInfo *instInfoStruct;
    /* basic sanity checks on the disassembled instruction */
    if(!ins->address || !ins->size) {
      break;
    }
    //printf("DEBUG26\n");
    d = d + ins->size;
    if (archi==1 || archi==2)
    {
	nop   = is_cs_nop_X86_ins(ins);
	ret   = is_cs_ret_X86_ins(ins);
	jmp   = is_cs_unconditional_jmp_X86_ins(ins);
	cflow = is_cs_cflow_ins(ins,archi);
	call  = is_cs_call_X86_ins(ins);
        condcflow = is_cs_conditional_cflow_X86_ins(ins);
    }
    else if (archi==3 || archi==4)
    {
	//we save the info to build the cfg
	//instInfoStruct.opcode       = ins->mnemonic;
	strcpy(instInfoStruct.opcode,ins->mnemonic); 
	//instInfoStruct.operands     = ins->op_str;
	strcpy(instInfoStruct.operands, ins->op_str);
	if (is_cs_conditional_cflow_ARM_ins(ins)==1 || (strcmp(ins->mnemonic, "ldrls")==0))
		instInfoStruct.isCond     = 2;
	else if (is_cs_unconditional_jmp_ARM_ins(ins)==1)
		instInfoStruct.isCond     = 1;
	else
		instInfoStruct.isCond     = 0;

	nop   = is_cs_nop_ARM_ins(ins);
	ret   = is_cs_ret_ARM_ins(ins);
	jmp   = is_cs_unconditional_jmp_ARM_ins(ins);
	cflow = is_cs_cflow_ins(ins,archi);
	call  = is_cs_call_ARM_ins(ins);
	//printf("DEBUG26\n");
	condcflow = is_cs_conditional_cflow_ARM_ins(ins);
	//if(ins->address == 125008 || ins->address == 125388 || ins->address == 125452 || ins->address == 125472)
	//	printf("****0x%jx    %s   %s  nop:%d ret:%d jmp:%d cflow:%d call:%d condcflow:%d\n", ins->address,ins->mnemonic,ins->op_str ,nop,ret,jmp,cflow,call,condcflow);
	//printf("DEBUG27\n");
	is_cs_LDR_ARM_ins(ins,smaps);
	//
	if(ins->id == ARM_INS_ADD  && (strstr({ins->op_str}, "pc,") != NULL) && (strstr({ins->op_str}, "#0x") != NULL || (strstr({ins->op_str}, "#-0x") != NULL)))
		is_cs_ARM_INS_ADD(ins,smaps);

	//mov r0, r0 instruction is the same as NOP
	/*if(ins->id ==ARM_INS_MOV &&  strcmp(ins->mnemonic, "mov")==0  &&(strstr({ins->op_str}, "r0, r0") != NULL))
	{	printf("****0x%jx    %s   %s \n", ins->address,ins->mnemonic,ins->op_str);
	}*/
	
	//printf("DEBUG28\n");
	is_cs_CMP_ins(ins);
	//printf("DEBUG29\n");
        if(strcmp(ins->mnemonic, "ldrls")==0) //getting the instruction for jump tables
        {
		is_cs_LDRLS_ARM_ins(smaps,ins,&instInfoStruct);
		//maybe it could be a load instr
		if (is_cs_LDRLS_ARM_ins(smaps,ins,&instInfoStruct)==0)
		{
			//printf("****0x%jx    %s   %s  nop:%d ret:%d jmp:%d cflow:%d call:%d\n", ins->address,ins->mnemonic,ins->op_str ,nop,ret,jmp,cflow,call);
			is_cs_LDRLS_ARM_ins2(smaps,ins);
		}
   	}
	
	//printf("****0x%jx    %s   %s\n", ins->address,instInfoStruct.opcode,instInfoStruct.operands ,instInfoStruct.isCond);
    }
    else
    {
	strcpy(instInfoStruct.opcode,ins->mnemonic); 
	//instInfoStruct.operands     = ins->op_str;
	strcpy(instInfoStruct.operands, ins->op_str);
	if (is_cs_conditional_cflow_MIPS_ins(ins)==1)
		instInfoStruct.isCond     = 2;
	else if (is_cs_unconditional_jmp_MIPS_ins(ins)==1)
		instInfoStruct.isCond     = 1;
	else
		instInfoStruct.isCond     = 0;
	instInfoStruct.targetSet = {};
	nop             = is_cs_nop_MIPS_ins(ins);
	ret             = is_cs_ret_MIPS_ins(ins);
	jmp             = is_cs_unconditional_jmp_MIPS_ins(ins);
	cflow           = is_cs_cflow_ins(ins,archi);
	call            = is_cs_call_MIPS_ins(ins);
	condcflow       = is_cs_conditional_cflow_MIPS_ins(ins);
        bal             = is_cs_BAL_MIPS_ins(ins);
        switchTargetSet = is_cs_SLTIU_MIPS_ins(ins,archi,elf,smaps,err); //if the current instruction is a jr instruction and it is going to jump to possible switch
        //targets we will get those switch targets in the switchTargetSet these targets will be jumped to after the next instruction (after jr)
	//debugging switch case for mips
	/*if (mipsSwitchSltiu!=-1)
	{
		printf("mipsSwitchSltiu==1  0x%jx    %s   %s  nop:%d ret:%d jmp:%d cflow:%d call:%d condcflow:%d bal:%d mipsSwitchSltiu:%d\n", ins->address,ins->mnemonic,ins->op_str ,nop,ret,jmp,cflow,call,condcflow,bal,mipsSwitchSltiu);
	}*/
	/*if (ins->address==4209936 ||ins->address==4212780||ins->address==4248836||ins->address==4268068)
		printf("2915::  0x%jx    %s   %s  nop:%d ret:%d jmp:%d cflow:%d call:%d condcflow:%d bal:%d mipsSwitchSltiu:%d\n", ins->address,ins->mnemonic,ins->op_str ,nop,ret,jmp,cflow,call,condcflow,bal,mipsSwitchSltiu);	
	if (ins->address==4209940 ||ins->address==4212784||ins->address==4248840||ins->address==4268072)
		printf("2915::  0x%jx    %s   %s  nop:%d InstrInfoMaps[prevInstAddr].isCond::%d\n", ins->address,ins->mnemonic,ins->op_str ,nop,InstrInfoMaps[ins->address-4].isCond);*/	
		
	if (switchTargetSet.size()>0)
	{
                /*if (mipsSwitchTargetsPresent==1)
		{
			//adding switch targets tp this instr
			for (std::set<uint64_t>::iterator it=switchTargetSet.begin(); it!=switchTargetSet.end(); ++it)
			{	
				instInfoStruct.targetSet.insert(*it);
				//InstrInfoMaps[ins->address].targetSet.insert(*it);
				//printf("\nInstrInfoMaps::ins->address::%jx   targetSet:: %jx", ins->address,*it);
			}
			mipsSwitchTargetsPresent=0; //reset the mipsSwitchTargetsPresent
			switchTargetSet.clear();          //clear the set
		}*/
		//printf("\nir instadd 0x%jx    %s   %s  switchTargetSet::%d", ins->address,ins->mnemonic,ins->op_str,switchTargetSet.size());
		for (std::set<uint64_t>::iterator it=switchTargetSet.begin(); it!=switchTargetSet.end(); ++it)
		{	
			//printf("\ntargetSet:: %jx", *it);
			instInfoStruct.targetSet.insert(*it);
			//InstrInfoMaps[ins->address+4].targetSet.insert(*it); //WRONG WAY
		}
		//mipsSwitchTargetsPresent = 1; //we will add these targets to after the next instruction

	}
	//debugging switch case for mips
	if (bal ==1)
        {
		//printf("bal==1  0x%jx    %s   %s  nop:%d ret:%d jmp:%d cflow:%d call:%d\n", ins->address,ins->mnemonic,ins->op_str ,nop,ret,jmp,cflow,call);
		for(int k = 0; k < ins->detail->mips.op_count; k++) 
		{
         		 mipsop = &ins->detail->mips.operands[k];
          		 if(mipsop->type == MIPS_OP_IMM) 
			 {
           			 t = mipsop->imm; 
				 //printf("bal==1  immediate 0x%jx    %s   %s    t=0x%jx \n", ins->address,ins->mnemonic,ins->op_str,t);
				 balInstInfo.balAddLoc = ins->address;
				 balInstInfo.balAddTarget = t;
				 balTargets.insert(balInstInfo);
			 }
		}
        }
	
    }

    ndisassembled++;
    if (!printInstSet.count(ins->address))
    {  	
	//printf("****0x%jx    %s   %s  nop:%d ret:%d jmp:%d condcflow:%d cflow:%d call:%d\n", ins->address,ins->mnemonic,ins->op_str ,nop,ret,jmp,condcflow,cflow,call);
	//printf(ins->bytes); //gives the type of this //‘uint8_t* {aka unsigned char*}’ to ‘const char*’ [-fpermissive]
	//printf("%d   \n",  *(ins->bytes)); //works
	//printf("0x%jx  0x%jx 0x%jx 0x%jx \n",  *(ins->bytes), *((ins+1)->bytes), *((ins+2)->bytes), *((ins+3)->bytes));
	//printf("%d\n",ins->address); //‘uint8_t* {aka unsigned char*}’ to ‘const char*’ [-fpermissive]

	//printInstSet.insert(ins->address);‘uint8_t* {aka unsigned char*}’ to ‘const char*’ [-fpermissive]
	//printf("****0x%jx    %s\n", ins->address,ins->mnemonic);
	//printf("0x%jx  0x%jx \n",  *(ins->bytes),*(ins->bytes + 1));
	//uint64_t jmptableadd1 =   *(ins->bytes+ 1) * 256 + *(ins->bytes) ;
	uint64_t jmptableadd1 =   *(ins->bytes+ 2) * 256 *256 + *(ins->bytes+ 1) * 256 + *(ins->bytes) ;
	/*if(ins->address>=321164 && ins->address<=322708)
	{	
		printf("ins->address::0x%jx  *(ins->bytes+ 2)::0x%jx   *(ins->bytes+ 1)::0x%jx  *(ins->bytes)::0x%jx \n", ins->address,*(ins->bytes+2),*(ins->bytes+1),*(ins->bytes));
		printf("2491::printInstSet.count(ins->address) ins->address::0x%jx    targetJumpAdd::0x%jx\n", ins->address,jmptableadd1);
	}*/
	instBytesMap[ins->address] = jmptableadd1;
    }
    //check for jmp table addresses
    if (jmpTableAddresses.count(ins->address))
    {
		BBStartAdd.insert(instBytesMap[ins->address]); 
		markBBForTargets (smaps,instBytesMap[ins->address]);
		//printf("****markBBForTargets ins->address::0x%jx instBytesMap[ins->address]::0x%jx    \n",ins->address,instBytesMap[ins->address]);
    }

    if(archi==5)
    {
	//for mips check if the prev inst was a direct uncond jump
	if(prevInstAddr!=0 && InstrInfoMaps[prevInstAddr].isCond==1 && InstrInfoMaps[prevInstAddr].targetSet.size()==1)
	{
		//printf("here,,, \n");
		for (auto it=InstrInfoMaps[prevInstAddr].targetSet.begin(); it != InstrInfoMaps[prevInstAddr].targetSet.end(); ++it) 
		{	
			//InstrInfoMaps[ins->address].targetSet.insert(*it);
			instInfoStruct.targetSet.insert(*it);
			//printf("targets..0x%jx  \n",*it);
		}
		//for mips empty the set for  prevprev inst 
		InstrInfoMaps[prevInstAddr].targetSet.clear();
	}
	//for mips check if the prev inst was a direct uncond jump
	if(prevInstAddr!=0 && InstrInfoMaps[prevInstAddr].isCond==1 && InstrInfoMaps[prevInstAddr].targetSet.size()>1)
	{
		//printf("here,,, \n");
		for (auto it=InstrInfoMaps[prevInstAddr].targetSet.begin(); it != InstrInfoMaps[prevInstAddr].targetSet.end(); ++it) 
		{	
			//InstrInfoMaps[ins->address].targetSet.insert(*it);
			instInfoStruct.targetSet.insert(*it);
			BBStartAdd.insert(*it); 
			globalTargets.insert(*it);
			markBBForTargets (smaps,*it);
			//printf("targets..0x%jx  \n",*it);
		}
		//for mips empty the set for  prevprev inst 
		InstrInfoMaps[prevInstAddr].targetSet.clear();
	}
	std::map<uint64_t, InstrInfo>::iterator it1 = InstrInfoMaps.find(ins->address);
	if(it1 != InstrInfoMaps.end())
	{
		if(InstrInfoMaps[ins->address].targetSet.size()>0) 
		{
			//for mips switch cases, sometimes the actual switch add is found, may not be found all the time
			//so we should keep the switch cases so that we do not lose the targets
			for (auto it=InstrInfoMaps[ins->address].targetSet.begin(); it != InstrInfoMaps[ins->address].targetSet.end(); ++it) 
			{
				instInfoStruct.targetSet.insert(*it);
				BBStartAdd.insert(*it); 
				globalTargets.insert(*it);
				markBBForTargets (smaps,*it);
			}
		}
	}
    }
    armCondInstr = armCondInstr -1;
    if(armCondInstr==0)
    {
	//printf("%d\n",ins->address);
	BBStartAdd.insert(ins->address); //instr after conditional jump target
	markBBForTargets (smaps,ins->address);
	//is_cs_BBMarkData_ARM_ins (ins->address,smaps,ret,cflow,call,nop);
	//armCondInstr =0;      //reset
	if(archi==5)
	{
		//for mips check if the prevprev inst was a direct cond jump
		if(InstrInfoMaps[prevInstAddr-4].isCond==2 && InstrInfoMaps[prevInstAddr-4].targetSet.size()==1)
		{
			for (auto it=InstrInfoMaps[prevInstAddr-4].targetSet.begin(); it != InstrInfoMaps[prevInstAddr-4].targetSet.end(); ++it) 
			{	
				InstrInfoMaps[prevInstAddr].targetSet.insert(*it);
				//printf("targets..0x%jx  \n",*it);
			}
			//for mips empty the set for  prevprev inst 
			InstrInfoMaps[prevInstAddr-4].targetSet.clear();	
		}
	}
	InstrInfoMaps[prevInstAddr].targetSet.insert(ins->address);
    }
    //creating BB after direct/indirect jump in mips
    bbAfterUncondJump = bbAfterUncondJump -1;
    if(bbAfterUncondJump ==0)
    {
	BBStartAdd.insert(ins->address); 
	markBBForTargets (smaps,ins->address);
	//printf("bbAfterUncondJump::0x%jx  \n",ins->address);
    }

    if(only_nop && !nop) {
      /* we've reached the end of the padding after a function */
      break;
    }
    /* ins->address is definitely an instruction boundary */
    b = btype_by_addr(smaps, ins->address);
    if(!b) {
      print_warn("suspected code byte at 0x%jx is outside selected sections", ins->address);
      if(ndisassembled > 1) {
        /* we've fallen through an instruction into nothing... this shouldn't normally happen */
        break;
      } else {
        (*err) = "instruction address points outside selected sections (1)";
        goto fail;
      }
    }
    verbose(2, "marking instruction boundary (1) at 0x%jx", ins->address);
    //if (ins->address ==97064)
    //printf("marking instruction boundary (1) at 0x%jx    %s    %d\n", ins->address,ins->mnemonic,ins->id);
    if((archi==3 || archi==4) && DataAddInCodeSeg.count(ins->address)) //Data Addr in Code Seg
    {
         b->mark(MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F,MAP_FLAG_F,MAP_FLAG_F,MAP_FLAG_F);
    }
    else if ((archi==3 || archi==4 ||archi==5) && BBStartAdd.count(ins->address))
    {
	is_cs_BBMarkData_ARM_ins (ins->address,smaps,ret,cflow,call,nop);
    }
    else
    {
    	b->mark(MAP_FLAG_T, MAP_FLAG_T, b->bbstart, b->funcstart, ret ? MAP_FLAG_t : b->funcend, cflow ? MAP_FLAG_T : MAP_FLAG_F, call ? MAP_FLAG_T : MAP_FLAG_F, b->progentry, nop ? MAP_FLAG_T : MAP_FLAG_F);
    }
    /* every other instruction byte is definitely code, and definitely
     * NOT any kind of boundary byte */
    for(i = (ins->address+1); i < (ins->address+ins->size); i++) {
      b = btype_by_addr(smaps, i);
      if(!b) {
        (*err) = "instruction address points outside selected sections (2)";
        goto fail;
      }
      verbose(2, "marking code byte at 0x%jx", i);
      //if (ins->address >97000)
      	//printf("*************marking instruction boundary (1) at  i= %d 0x%jx    %s   %d \n", i, ins->address,ins->mnemonic,ins->id);
      if((archi==3 || archi==4) && DataAddInCodeSeg.count(ins->address)) //Data Addr in Code Seg only for arm
      {
      	b->mark(MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F,MAP_FLAG_F,MAP_FLAG_F,MAP_FLAG_F);
      }
      else if ((archi==3 || archi==4||archi==5) && BBStartAdd.count(ins->address))
      {
	is_cs_BBMarkData_ARM_ins (ins->address,smaps,ret,cflow,call,nop);
      }
      else
      {
    	b->mark(MAP_FLAG_T, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, nop ? MAP_FLAG_T : MAP_FLAG_F);
      }
      
    }
    	
    /* special treatment for control-flow instructions to guarantee that we
     * proceed or stop in a reliable way */
    cflowSaved = cflow;
    cflow = 0;
    //handle pop{cond} instructions
    if ((archi==3 || archi==4) && is_popCond_ARM_ins(ins)==1)
    {
    	//printf("****line2274:: armCondInstr =1\n"); 
	armCondInstr =1; 	
    }
    //inst after ldrls should be new BB
    if ((archi==3 || archi==4) &&is_cs_LDRLS_ARM_ins(smaps,ins,&instInfoStruct)==1)
    {
	armCondInstr =1; 
    }
    for(i = 0; i < ins->detail->groups_count; i++) {
      if(is_cs_cflow_group(ins->detail->groups[i])) { //for diff archis
        /* queue direct control-flow targets to be recursively disassembled */
        if (archi==1 || archi==2) {
        for(j = 0; j < ins->detail->x86.op_count; j++) {
          op = &ins->detail->x86.operands[j];
          if(op->type == X86_OP_IMM) {
            t = op->imm;
            sec = section_map_by_addr(smaps, t);
            if(sec && !sec->dismap.count(t)) {
              verbose(2, "queueing control flow target 0x%jx (0x%jx -> 0x%jx) for recursive disassembly", t, ins->address, t);
              targets->insert(t);
	      globalTargets.insert(t);
            }
          }
        }}
        if (archi==3 || archi==4) {
	//printf("****line2266::\n");
	for(j = 0; j < ins->detail->arm.op_count; j++) {
          armop = &ins->detail->arm.operands[j];
          if(armop->type == ARM_OP_IMM) {
            t = armop->imm;
            sec = section_map_by_addr(smaps, t);
            if(sec && !sec->dismap.count(t)) {
              verbose(2, "queueing control flow target 0x%jx (0x%jx -> 0x%jx) for recursive disassembly", t, ins->address, t);
              targets->insert(t);
            }
            if (is_cs_conditional_cflow_ARM_ins(ins)==1)
	    {
		BBStartAdd.insert(t); //conditional jump target
		globalTargets.insert(t);
		markBBForTargets (smaps,t);
		instInfoStruct.targetSet.insert(t);
		armCondInstr =1;  
	    }
	    if(jmp==1)
	    {  
		BBStartAdd.insert(t);
		globalTargets.insert(t);
		markBBForTargets (smaps,t);
		instInfoStruct.targetSet.insert(t);
	    }
          }//if(armop->type == ARM_OP_IMM) {
	  //for unconditional indirect jumps
          else
	  { 
		  if (is_cs_conditional_cflow_ARM_ins(ins)==1)
		  {
			armCondInstr =1;  
			//printf("****line2295:: armCondInstr =1\n");  
		  }
	  }
	
        } //for loop
	//printf("****line2299::\n"); 
	//if (is_cs_conditional_cflow_ARM_ins(ins)==1) //for pop{cond}
	//{
	//		armCondInstr =1;  
	//		printf("****line2302:: armCondInstr =1\n");  
	//}
	} //archi 3 and 4 
        if (archi==5) {
	for(j = 0; j < ins->detail->mips.op_count; j++) {
          mipsop = &ins->detail->mips.operands[j];
          if(mipsop->type == MIPS_OP_IMM) {
            t = mipsop->imm;
            sec = section_map_by_addr(smaps, t);
            if(sec && !sec->dismap.count(t)) {
              verbose(2, "queueing control flow target 0x%jx (0x%jx -> 0x%jx) for recursive disassembly", t, ins->address, t);
              targets->insert(t);
            }//if(sec && !sec->dismap.count(t))
	    if (is_cs_conditional_cflow_MIPS_ins(ins)==1)
	    {
		//printf("cs_conditional_cflow direct mips  i= %d 0x%jx    %s   %s \n", i, ins->address,ins->mnemonic,ins->op_str);
		BBStartAdd.insert(t); //conditional jump target
		globalTargets.insert(t);
		markBBForTargets (smaps,t);
		instInfoStruct.targetSet.insert(t);
		armCondInstr =2;  
	    }
	    if(jmp==1)
	    {  
		//printf("jmp direct mips  i= %d 0x%jx    %s   %s \n", i, ins->address,ins->mnemonic,ins->op_str);
		BBStartAdd.insert(t);
		globalTargets.insert(t);
		markBBForTargets (smaps,t);
		instInfoStruct.targetSet.insert(t);
		//the instruction (+1) after the uncond direct jump has to be a BB
		bbAfterUncondJump =2;
	    }
          }//if(mipsop->type == MIPS_OP_IMM) 
	  //for conditional indirect jumps
          else
	  { 
		  if (is_cs_conditional_cflow_MIPS_ins(ins)==1)
		  {
			//printf("cs_conditional_cflow indirect mips  i= %d 0x%jx    %s   %s \n", i, ins->address,ins->mnemonic,ins->op_str);
			armCondInstr = 2;    
		  }
		  if(jmp==1)
		  {
			bbAfterUncondJump = 2;
		  }
	  }
        }}// if (archi==5),//for(j = 0; j < ins->detail->mips.op_count; j++)
        if((ret && !ignore_padding) || (jmp && !ignore_padding)) {
          /* keep looking for padding (NOPs) after the ret or jmp */
          if (archi==1||archi==2)//for x86_64 archis
          	only_nop = 1;
          break;
        }
        if(condcflow && !ignore_fallthrough) {
          /* we can safely assume fallthrough blocks for conditional jumps,
           * unless there may be opaque predicates (then -j should be passed) */ 
          break;
        }
        if(call && guess_return) {
          /* if guess_return is true, we assume calls return to the following 
           * instruction (XXX: may not be true for malicious code or leaf functions) */
          break;
        }

        cflow = 1;
        break;
      }
    }
    if(cflow) {
      break;
    }
    //adding inst info
    prevInstAddr = ins->address;
    InstrInfo *instInfoStruct1;
    instInfoStruct1 = &instInfoStruct;
    InstrInfoMaps[ins->address] = *instInfoStruct1;
    //printf("****end ins->address..0x%jx  %s  %s  %d %s\n",ins->address,InstrInfoMaps[ins->address].opcode,InstrInfoMaps[ins->address].operands,InstrInfoMaps[ins->address].isCond,InstrInfoMaps[ins->address].targetSet);
     //printf("****end ins->address2..0x%jx  %s  %s  %d %d\n",ins->address-4,InstrInfoMaps[ins->address-4].opcode,InstrInfoMaps[ins->address-4].operands,InstrInfoMaps[ins->address-4].isCond,InstrInfoMaps[ins->address-4].targetSet.size());
     //printf(InstrInfoMaps[ins->address-4].targetSet)


/*if (InstrInfoMaps[ins->address-4].targetSet.size()>0)
   {
	for (auto it=InstrInfoMaps[ins->address-4].targetSet.begin(); it != InstrInfoMaps[ins->address-4].targetSet.end(); ++it) 
		printf("targets..0x%jx  \n",*it);
   }*/
  }
  if (cflow==0)
  	nexInstAddrToCont = ins->address;
  // release the cache memory when done


  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(ins) {
    cs_free(ins, 1);
  }
  if(init) {
    cs_close(&dis);
  }
  //return ret;
  return cflow;
}
int safe_disasm_linear1( uint8_t *code, int nBytes,uint64_t addStart)
{
	const char *dataOps[32] = {"andeq","muleq","strheq","cdpmi","stmlo","movweq","strdeq","ldreq","strheq","addhi","rscsls","ldrdeq","strthi","svcgt","andhi","ldrbpl","stmdaeq","strbeq","andhi","uqusxvs","svclo","stmlt","strbtvs","movweq","strbeq","stmhi",
	"strblo","stclgt","bhs","eoreq","mlaeq","strhteq"};
 	const uint8_t *pc;
        //char *lastMneu;
	//String lastMneu="";
	char lastMneu[80];
  	uint64_t pcaddr =addStart;
	size_t n =0;
  	//size_t n =400; //lets me see 100 instructions at max
        if (nBytes==400)
        	n =400;
        if (nBytes==40)
        	n =40;
	int counter =0; //instruction index
        int lastCodeIdx=0;
	int data=0;
	csh dis;
  	pc = code;
	cs_insn *ins;
	cs_mode mode = CS_MODE_ARM;
 	if(cs_open(CS_ARCH_ARM, mode, &dis) != CS_ERR_OK) 
	{
		printf("failed to initialize libcapstone\n");
	    	return 0;
	}
	int init = 1;
	cs_option(dis, CS_OPT_DETAIL, CS_OPT_ON);
  	cs_option(dis, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
	ins = cs_malloc(dis);
	while (counter<(nBytes/4)){
	while(cs_disasm_iter(dis, &pc, &n, &pcaddr, ins) && (counter<(nBytes/4)) )
	{
		//lastMneu = new const char;
                data =0;
    		if(!ins->address || !ins->size) 
		{
      			break;
    		}
		if(ins==NULL)
			printf("insn is NULL\n");
		else
		{	
			printf("\n%d::safe_disasm_linear111::****0x%jx    %s   %s  ",counter,ins->address,ins->mnemonic,ins->op_str);
			for (int i=0; i<32;i++)
			{
				if(strcmp(dataOps[i],ins->mnemonic)==0)
				{
					data=1;
					//printf(" data=1\n");
				}
			}
			counter++; //update instr index
			if (data==0)
			{	
				lastCodeIdx = counter;
				//lastMneu = ins->mnemonic;
				//printf("  lastMneu::%s \n",lastMneu);
				strcpy(lastMneu, ins->mnemonic);
				printf("  lastMneu::%s \n",lastMneu);
				//counter++;
				//printf("\ncounter::%d ", counter);
				
			}
		}		
		//printf("    %s   %s  \n",dataOps[0],dataOps[25] );

	}
	printf("\ncounter::%i  lastCodeIdx::%i lastPneu::%s nBytes::%i  n::%i  n/4::%i   \n",counter,lastCodeIdx,lastMneu,nBytes,n,(n/4));
	pcaddr = pcaddr +4;
	pc=pc+4;
	counter++;
	}//outer while loop
	if(ins) {
    		cs_free(ins, 1);
  	}
	if(init){
   		 cs_close(&dis);
  	}
	return lastCodeIdx ; 
}
//writing to a file
//https://www.programiz.com/c-programming/c-file-input-output
int
safe_disasm(elf_data_t *elf, std::vector<section_map_t> *smaps, uint64_t addr, char const **err)
{
  int ret;
  uint8_t code[CODE_CHUNK_SIZE];
  size_t len;
  size_t len_temp =100;//reads these number of bytes
  std::set<uint64_t> targets;
  uint64_t t;
  int intt;
  int returnedCode=0;
  uint64_t targetJumpAdd =0;
  //writing info into a file
  int num;
  int codeIdx=0;
  FILE *fptr;
  //fptr = fopen("/home/shaila/Desktop/Project/GetGndTruthFromDwarf/myElfmapCode/getBytesArdF/FunctionInfo1.txt","a");
  //funcBytesInfoT xt
  fptr = fopen(funcBytesInfoTxt,"a");
  //printf("\nfuncStartAddSet.size()::%d",funcStartAddSet.size());
  
  if(fptr == NULL)
  {
      printf("Error!");   
      exit(1);             
  }

  targets.insert(addr);
  globalTargets.insert(addr);
  //while(!targets.empty()) { //original
    while(!funcStartAddSet.empty()) { 
    t = (*funcStartAddSet.begin());
    intt = t;
    funcStartAddSet.erase(t);
    if (t==0)
	continue;
    printf("\nfunc add::%jx",t);
    printf("\nmlAddDetails[t]::%s",mlAddDetails[t]);
    //remove the \n from mlAddDetails[t]
    size_t lenOfString = strlen(mlAddDetails[intt]);
    /*if (lenOfString>0 && mlAddDetails[intt][lenOfString-2] == '\n')
    {
	    printf("hereee.....12345\n");
	    mlAddDetails[intt][lenOfString-2] = '\0';
    }*/
    mlAddDetails[intt][lenOfString-1] = '\0';
    //printf("char last :: %c\n",mlAddDetails[intt][lenOfString-1]);
    //printf("char 2nd last :: %c\n",mlAddDetails[intt][lenOfString-2]);
    //fprintf(fptr,"func add::%jx  start add::%jx\n",t,t-8);
    fprintf(fptr,"%s,",mlAddDetails[intt]);
    //For ARM
    /*len = 400;//so that capstone can read 100 instructions b4 start at max
    //this is to get the last code bytes
    if(read_elf_section_by_addr(elf, smaps, t-400, code, &len, err) < 0) {
      printf("\nfunc add::%jx fail...",t);
      goto fail;
    }
    else
    {
	codeIdx =safe_disasm_linear1(code,400,t-400);
	if(codeIdx>=2)
	{
		printf("2inst bytes b4...\n");
		for(int loop = (codeIdx-2)*4 ; loop <(codeIdx-2)*4+8; loop++)
		{
			fprintf(fptr,"%jx,",code[loop]);
			printf("%jx  ",code[loop]);
		}
	}
	else
	{
		//prob the first instr so we could not get 400 bytes before it
    		if(read_elf_section_by_addr(elf, smaps, t-40, code, &len, err) < 0) 
		{ //t-12 gets is needed for capstone to get 100  before func start at max, somtimes data not shown
      			printf("\nfunc add::%jx fail...",t);
      			goto fail;
    		}
		codeIdx = safe_disasm_linear1(code,40,t-40);
		if(codeIdx>=2)
		{
			printf("2inst bytes b4...\n");
			for(int loop = (codeIdx-2)*4 ; loop <(codeIdx-2)*4+8; loop++)
			{
				fprintf(fptr,"%jx,",code[loop]);
				printf("%jx  ",code[loop]);
			}
		}
		else
			fprintf(fptr,"0,0,0,0,0,0,0,0,");//fill up with 8 * "-1"
	}
    }*/ 
    
    //comment this out for mips
    //this is to get the last code bytes
    //getting 8 bytes before start
    memset(code, 0, sizeof(code));
    len= 8; //original for arm
    //len= 12; //original for arm
    //if(read_elf_section_by_addr(elf, smaps, t-8, code, &len, err) < 0) { //t-12 gets is needed for capstone to get 2 inst before and after, t-8 for mips
    if(read_elf_section_by_addr(elf, smaps, t-8, code, &len, err) < 0) {
      printf("\nfunc add::%jx fail...",t);
      goto fail;
    }
    else
    {
	//safe_disasm_linear1(code);
	printf("\nfunc add::%jx bytes before...\n",t);
    	//here we print the info to the text file
	for(int loop = 0; loop <len; loop++)
	{
		printf("%jx ",code[loop]);
		fprintf(fptr,"%jx,",code[loop]);
	}
    }
    //mips 8bytes from the start
    memset(code, 0, sizeof(code));
    len= 8; //original for arm
    //len= 12; //12 bytes arm
    if(read_elf_section_by_addr(elf, smaps, t-0, code, &len, err) < 0) { 
      printf("\nfunc add::%jx fail...",t);
      goto fail;
    }
    else
    {
	//safe_disasm_linear1(code);
	printf("\nfunc add::%jx bytes after...\n",t);
    	//here we print the info to the text file
	for(int loop = 0; loop <len; loop++)
	{
		printf("%jx ",code[loop]);
		if(loop == len-1)
			fprintf(fptr,"%jx\n",code[loop]);
		else
			fprintf(fptr,"%jx,",code[loop]);
	}
    }
    //printf("DEBUG24\n");
    //original
    /*if(safe_disasm_linear(elf, smaps, &targets, t, code, len, err) < 0) {
      goto fail;
    }*/
    //original
    /*returnedCode = safe_disasm_linear(elf, smaps, &targets, t, code, len, err);
    if(returnedCode<0)
	goto fail;
    if (returnedCode==0)
    {
        if(read_elf_section_by_addr(elf, smaps, nexInstAddrToCont, code, &len_temp, err) < 0) 
	{
	      printf("failed....\n");
	      goto fail;
	}
	//for(int loop = 3; loop <(len_temp*4); loop= loop+4)
	for(int loop = 3; loop <len_temp; loop= loop+4)
      	{	
		if (!printInstSet.count(nexInstAddrToCont))
   		{  
			targetJumpAdd = code[loop]*256*256*256 + code[loop-1]*256*256 + code[loop-2]*256 + code[loop-3];
			//if(nexInstAddrToCont>=321164 && nexInstAddrToCont<=322708)
			//	printf(" 2837:nexInstAddrToCont::0x%jx    targetJumpAdd::0x%jx\n", nexInstAddrToCont,targetJumpAdd);
		
		//printf("%d ", code[loop]);
	
			//uint64_t jmptableadd1 =   *(ins->bytes+ 2) * 256 *256 + *(ins->bytes+ 1) * 256 + *(ins->bytes) ;
			//if(ins->address>=258520 && ins->address<=258600)
				//printf("ins->address::0x%jx  *(ins->bytes+ 2)::0x%jx   *(ins->bytes+ 1)::0x%jx  *(ins->bytes)::0x%jx \n", ins->address,*(ins->bytes+2),*(ins->bytes+1),*(ins->bytes));
			instBytesMap[nexInstAddrToCont] = targetJumpAdd;
    		}
		nexInstAddrToCont = nexInstAddrToCont +4;
	}
	//safe_disasm_linear(elf, smaps, &targets, nexInstAddrToCont, code, 40, err);
    }*/
    //redo if cflow==0
    
  }
  fclose(fptr);
  //printf("DEBUG25\n");
  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}



int
parse_dwarf_cu_die(elf_data_t *elf, Dwarf_Die die, std::vector<section_map_t> *smaps, char const **err)
{
  int ret;
  char *diename, *lnsrc;
  Dwarf_Error dwerr;
  Dwarf_Line *lines;
  Dwarf_Signed i, nlines;
  Dwarf_Unsigned lineno;
  Dwarf_Addr addr;
  btype_t *b;

  lines = NULL;

  if(dwarf_diename(die, &diename, &dwerr) != DW_DLV_OK) {
    diename = NULL;
  }

  verbose(2, "parsing line information for object '%s'", safe_diename(diename));

  if(dwarf_srclines(die, &lines, &nlines, &dwerr) != DW_DLV_OK) {
    (*err) = "failed to get DWARF line information";
    goto fail;
  }

  for(i = 0; i < nlines; i++) {
    if(dwarf_lineno(lines[i], &lineno, &dwerr) != DW_DLV_OK) {
      (*err) = "failed to get DWARF line number information";
      goto fail;
    }
    if(dwarf_lineaddr(lines[i], &addr, &dwerr) != DW_DLV_OK) {
      (*err) = "failed to get DWARF line to instruction mapping";
      goto fail;
    }
    if(dwarf_linesrc(lines[i], &lnsrc, &dwerr) != DW_DLV_OK) {
      lnsrc = (char*)"[unknown file]";
    }
 
    b = btype_by_addr(smaps, addr);
    if(!b) {
      print_warn("skipping dangling DWARF instruction mapping at 0x%jx (%s: %u)", addr, lnsrc, lineno);
      continue;
    }

    verbose(2, "marking instruction boundary (2) at 0x%jx (%s: %u)", addr, lnsrc, lineno);
    b->mark(MAP_FLAG_T, MAP_FLAG_T, b->bbstart, b->funcstart, b->funcend, b->cflow, b->call, b->progentry, b->nop);

    /* this is an instruction boundary, so it's a safe start for conservative disassembly */
    if(safe_disasm(elf, smaps, addr, err) < 0) {
      goto fail;
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(lines) {
    dwarf_srclines_dealloc(elf->dwarf, lines, nlines);
  }

  return ret;
}


int parse_dwarf_func_ins(elf_data_t *elf, Dwarf_Die die, std::vector<section_map_t> *smaps, char const **err)
{
  int ret;
  char *diename;
  Dwarf_Error dwerr;
  Dwarf_Attribute *attrs;
  Dwarf_Signed i, nattrs;
  Dwarf_Half attrtype;
  Dwarf_Addr lowpc, highpc, entrypc;
  bool hirel;
  btype_t *b,*updateBBb;

  attrs = NULL;

  if(dwarf_diename(die, &diename, &dwerr) != DW_DLV_OK) {
    diename = NULL;
  }

  if(dwarf_attrlist(die, &attrs, &nattrs, &dwerr) != DW_DLV_OK) {
    (*err) = "failed to get DWARF attributes for function entry";
    goto fail;
  }

  lowpc   = 0;
  highpc  = 0;
  entrypc = 0;
  hirel   = false;
  for(i = 0; i < nattrs; i++) {
    if(dwarf_whatattr(attrs[i], &attrtype, &dwerr) != DW_DLV_OK) {
      (*err) = "failed to determine DWARF attribute type";
      goto fail;
    }

    switch(attrtype) {
    case DW_AT_low_pc:
      dwarf_formaddr(attrs[i], &lowpc, &dwerr);
      break;

    case DW_AT_high_pc:
      if(resolve_dwarf_high_pc(attrs[i], (uint64_t*)&highpc, &hirel, err) < 0) {
        goto fail;
      }
      break;

    case DW_AT_ranges:   /* DWARF v3 */
      /* TODO: this tells all the instruction ranges for functions that are
       * not contiguous in memory. Implement if we ever see this case. */
      (*err) = "DW_AT_ranges attribute not supported -- looks like it's time to implement it :-)";
      goto fail;

    case DW_AT_entry_pc: /* DWARF v3 */
      dwarf_formaddr(attrs[i], &entrypc, &dwerr);
      break;

    default:
      continue;
    }
  }
  if(hirel) highpc += lowpc;
  if((lowpc > 0) && (highpc > lowpc) && ((entrypc > 0) || guess_func_entry)) {
    if(!entrypc) {
      print_warn("guessing entry point 0x%lx for function '%s'", lowpc, safe_diename(diename));
      entrypc = lowpc;
    }

    b = btype_by_addr(smaps, entrypc);
    if(!b) {
      (*err) = "DWARF instruction mapping points outside selected sections";
      goto fail;
    }
    verbose(2, "marking function entry at 0x%jx", entrypc);
    //printf("/n 1.marking function start :: 0x%jx  \n", entrypc);
    globalFuncStarts.insert(entrypc);
    globalFuncStartsVect.push_back(entrypc);
    b->mark(MAP_FLAG_T, MAP_FLAG_T, MAP_FLAG_T, MAP_FLAG_T, b->funcend, b->cflow, b->call, b->progentry, b->nop);
    //globalTargets.clear();
    //balTargets.clear();
    //printf("globalTargets start size :: %d  \n", globalTargets.size());
    /* start a disassembly pass at the function entry point */
    if(safe_disasm(elf, smaps, entrypc, err) < 0) {
      goto fail;
    }
 
    //for bal instructions
    
    //std::set<balInfo>::iterator it1;
    // uint64_t    balAddLoc;         /* ELF entry point     */
    //uint64_t    balAddTarget; 
    //printf("balTargets end size :: %d  \n", balTargets.size());
    /*for (it1 =balTargets.begin(); it1 != balTargets.end(); ++it1)
    {
        //printf("balInstAddLoc :: 0x%jx  \n", it1->balAddLoc);
        //printf("balAddTarget :: 0x%jx  \n", it1->balAddTarget);
	if(lowpc<=it1->balAddTarget && it1->balAddTarget<highpc)
	{
		//printf("balInstTargets :: 0x%jx  \n", it1->balAddTarget);
		updateBBb = btype_by_addr(smaps, it1->balAddTarget);
		if(!updateBBb) 
		{
		      (*err) = "DWARF instruction mapping points outside selected sections::updateBBb failed";
		      goto fail;
		}
		updateBBb->bbstart = MAP_FLAG_T;
		
		
		updateBBb = btype_by_addr(smaps, it1->balAddLoc+4);
		if(!updateBBb) 
		{
		      (*err) = "DWARF instruction mapping points outside selected sections::updateBBb failed";
		      goto fail;
		}
		updateBBb->bbstart = MAP_FLAG_T;
	}
    }*/
    //printf("globalTargets end size :: %d  \n", globalTargets.size());
    //globalTargets.clear(); //clear the set
    //balTargets.clear();
    //shaila::checking the BB blocks identified for this func
  } else {
    print_warn("skipping disassembly of function '%s' at range [0x%lx, 0x%lx] with entry 0x%lx)", 
               safe_diename(diename), lowpc, highpc, entrypc);
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}


int
parse_dwarf_data_type_str(elf_data_t *elf, Dwarf_Die child, std::string &s, char const **err)
{
  Dwarf_Error dwerr;
  char *diename, *mangled_name;
  Dwarf_Half tag;
  Dwarf_Attribute a;
  std::string delim, objtype;
  bool voidptr;

  voidptr = false;
  while(1) {
    if(dwarf_tag(child, &tag, &dwerr) != DW_DLV_OK) {
      (*err) = "failed to read DWARF DIE tag";
      return -1;
    }

    if(dwarf_diename(child, &diename, &dwerr) != DW_DLV_OK) {
      diename = NULL;
    }

    if((dwarf_attr(child, DW_AT_MIPS_linkage_name, &a, &dwerr) == DW_DLV_OK)
       || (dwarf_attr(child, DW_AT_linkage_name, &a, &dwerr) == DW_DLV_OK)) {
      dwarf_formstring(a, &mangled_name, &dwerr);
      if(!diename) diename = mangled_name;
    }

    delim = s.empty() ? "" : " ";
    switch(tag) {
    case DW_TAG_formal_parameter:
      if(diename) {
        s.insert(0, diename + delim);
      }
      break;

    case DW_TAG_base_type:
      if(!diename) {
        (*err) = "unnamed DWARF base type entry";
	diename = "unnamed DWARF base type entry";
        return -1; 
      }
      s.insert(0, diename + delim);
      voidptr = false;
      break;

    case DW_TAG_pointer_type:
    case DW_TAG_ptr_to_member_type:
      s.insert(0, "*");
      voidptr = true;
      break;

    objtype = "";
    case DW_TAG_structure_type:
      if(objtype.empty()) objtype = "struct "; /* fall through */
    case DW_TAG_enumeration_type:
      if(objtype.empty()) objtype = "enum ";   /* fall through */
    case DW_TAG_class_type:
      if(objtype.empty()) objtype = "class ";  /* fall through */
    case DW_TAG_union_type:
      if(objtype.empty()) objtype = "union ";
      s.insert(0, objtype + diename + delim);
      voidptr = false;
      break;

    case DW_TAG_array_type:
      s.insert(0, "[]");
      break;
    case DW_TAG_subrange_type:
      break;

    case DW_TAG_const_type:
    case DW_TAG_typedef:
    case DW_TAG_volatile_type:
    case DW_TAG_restrict_type:
    case DW_TAG_mutable_type:
    default:
      /* silently ignore irrelevant tags */
      break;
    }

    if(dwarf_attr(child, DW_AT_type, &a, &dwerr) == DW_DLV_OK) {
      if(resolve_dwarf_die_ref(elf->dwarf, a, &child, err) < 0) {
        return -1;
      }
    } else {
      if(voidptr) {
        /* void pointers don't have explicitly named base types */
        s.insert(0, "void" + delim);
      }
      break;
    }
  }

  return 0;
}


int parse_dwarf_func_sig(elf_data_t *elf, Dwarf_Die die, 
                         std::vector<section_map_t> *smaps, std::vector<function_t> *funcs, 
                         char const **err)
{
  int ret;
  bool inlined, hirel;
  size_t n;
  char *diename, *mangled_name;
  Dwarf_Error dwerr;
  Dwarf_Die resolved_die, child;
  Dwarf_Attribute *attrs, a;
  Dwarf_Signed i, nattrs, attrdata;
  Dwarf_Half attrtype, tag;
  Dwarf_Addr lowpc, highpc;
  std::string rettype;
  function_t *f;

  attrs = NULL;

  mangled_name = NULL;
  resolved_die = die;
  if((dwarf_attr(resolved_die, DW_AT_MIPS_linkage_name, &a, &dwerr) == DW_DLV_OK)
     || (dwarf_attr(resolved_die, DW_AT_linkage_name, &a, &dwerr) == DW_DLV_OK)) {
    dwarf_formstring(a, &mangled_name, &dwerr);
    /* g++ encodes DW_AT_MIPS_linkage_name in a separate DIE which refers to
     * the real function DIE via DW_AT_abstract_origin */
    if(dwarf_attr(resolved_die, DW_AT_abstract_origin, &a, &dwerr) == DW_DLV_OK) {
      if(resolve_dwarf_die_ref(elf->dwarf, a, &resolved_die, err) < 0) {
        /* XXX: don't fail; the name should get properly demangled 
         *      by the function_t constructor anyway */
        resolved_die = die;
        /*goto fail;*/
      }
    }
  }

  if(dwarf_diename(resolved_die, &diename, &dwerr) != DW_DLV_OK) {
    diename = NULL;
  }
  if(!diename) {
    /* skip unnamed functions */
    return 0;
  }
  verbose(3, "parse_dwarf_func_sig: parsing function %s (%s)", diename, mangled_name ? mangled_name : "");

  if(dwarf_attrlist(resolved_die, &attrs, &nattrs, &dwerr) != DW_DLV_OK) {
    (*err) = "failed to get DWARF attributes for function entry";
    goto fail;
  }

  lowpc   = 0;
  highpc  = 0;
  hirel   = false;
  inlined = false;
  rettype = "";
  for(i = 0; i < nattrs; i++) {
    if(dwarf_whatattr(attrs[i], &attrtype, &dwerr) != DW_DLV_OK) {
      (*err) = "failed to determine DWARF attribute type";
      goto fail;
    }

    switch(attrtype) {
    case DW_AT_low_pc:
      dwarf_formaddr(attrs[i], &lowpc, &dwerr);
      break;

    case DW_AT_high_pc:
      if(resolve_dwarf_high_pc(attrs[i], (uint64_t*)&highpc, &hirel, err) < 0) {
        goto fail;
      }
      break;

    case DW_AT_inline:
      dwarf_formsdata(attrs[i], &attrdata, &dwerr);
      if((attrdata == DW_INL_inlined) || (attrdata == DW_INL_declared_inlined)) {
        inlined = true;
      }
      break;

    case DW_AT_type:
      if(!have_llvminfo) {
        /* return type (get it from DWARF only if we don't have llvm info) */
        if(resolve_dwarf_die_ref(elf->dwarf, attrs[i], &child, err) < 0) {
          goto fail;
        }
        if(parse_dwarf_data_type_str(elf, child, rettype, err) < 0) {
          goto fail;
        }
      }
      break;

    default:
      continue;
    }
  }

  if(hirel) highpc += lowpc;

  f = NULL;
  for(n = 0; n < funcs->size(); n++) {
    if((mangled_name && !funcs->at(n).mangled_name.compare(mangled_name)) 
       || (!mangled_name && !funcs->at(n).name.compare(diename))) {
      verbose(3, "parse_dwarf_func_sig: merging into function %s (%s)", 
              funcs->at(n).name.c_str(), funcs->at(n).mangled_name.c_str());
      f = &funcs->at(n);
    }
  }
  if(!f) {
    verbose(3, "parse_dwarf_func_sig: creating new function %s (%s)", diename, mangled_name ? mangled_name : "");
    if(mangled_name) {
      funcs->push_back(function_t(mangled_name, lowpc, highpc-lowpc));
    } else {
      funcs->push_back(function_t(diename, lowpc, highpc-lowpc));
    }
    f = &funcs->back();
  }

  /*
  f->name = std::string(diename);
  if(mangled_name) {
    f->mangled_name = std::string(mangled_name);
  }
  */

  if(inlined) {
    f->inlined = true;
  }

  if(!have_llvminfo) {
    if(rettype.empty()) {
      f->ret = "void";
    } else {
      f->ret = rettype;
    }

    /* function parameters (get them from DWARF only if we don't have llvm info) */
    n = 0;
    f->params.clear();
    while(1) {
      if(n++) {
        ret = dwarf_siblingof(elf->dwarf, child, &child, &dwerr);
      } else {
        ret = dwarf_child(resolved_die, &child, &dwerr);
      }
  
      if(ret == DW_DLV_ERROR) {
        (*err) = "failed to read DWARF debugging entry (1)";
        goto fail;
      } else if(ret == DW_DLV_NO_ENTRY) {
        break;
      }
  
      if(dwarf_tag(child, &tag, &dwerr) != DW_DLV_OK) {
        (*err) = "failed to read DWARF DIE tag";
        goto fail;
      }
  
      if(tag == DW_TAG_formal_parameter) {
        f->params.push_back("");
        if(parse_dwarf_data_type_str(elf, child, f->params.back(), err) < 0) {
          goto fail;
        }
      }
    }
    f->valid_sig = true;
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}


int
parse_dwarf_data_location(elf_data_t *elf, Dwarf_Attribute attr, std::vector<section_map_t> *smaps, char const **err)
{
#if 0
  int ret;
  Dwarf_Error dwerr;
  Dwarf_Signed i, j, nloc;
  Dwarf_Locdesc **locbuf;
  Dwarf_Locdesc *locdesc;
  Dwarf_Loc *loc;

  locbuf = NULL;

  if(dwarf_loclist_n(attr, &locbuf, &nloc, &dwerr) != DW_DLV_OK) {
    (*err) = "failed to parse DWARF data location descriptor";
    goto fail;
  }

  for(i = 0; i < nloc; i++) {
    locdesc = locbuf[i];
    if(locdesc->ld_lopc > 0 && locdesc->ld_hipc > 0) {
      /* XXX */
    }
    for(j = 0; j < locdesc->ld_cents; j++) {
      loc = &locdesc->ld_s[j];
      /* TODO: parse loc */
    }
    dwarf_dealloc(elf->dwarf, locdesc->ld_s, DW_DLA_LOC_BLOCK);
    dwarf_dealloc(elf->dwarf, locdesc, DW_DLA_LOCDESC);
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(locbuf) {
    dwarf_dealloc(elf->dwarf, locbuf, DW_DLA_LIST);
  }

  return ret;
#else /* XXX: not implemented */
  return 0;
#endif
}


int parse_dwarf_data_die(elf_data_t *elf, Dwarf_Die die, std::vector<section_map_t> *smaps, char const **err)
{
  int ret;
  char *diename;
  Dwarf_Error dwerr;
  Dwarf_Attribute *attrs;
  Dwarf_Signed i, nattrs;
  Dwarf_Half attrtype;

  if(dwarf_diename(die, &diename, &dwerr) != DW_DLV_OK) {
    diename = NULL;
  }

  if(dwarf_attrlist(die, &attrs, &nattrs, &dwerr) != DW_DLV_OK) {
    (*err) = "failed to get DWARF attributes for variable/parameter/constant entry";
    goto fail;
  }

  for(i = 0; i < nattrs; i++) {
    if(dwarf_whatattr(attrs[i], &attrtype, &dwerr) != DW_DLV_OK) {
      (*err) = "failed to determine DWARF attribute type";
      goto fail;
    }

    switch(attrtype) {
    case DW_AT_location:
      if(parse_dwarf_data_location(elf, attrs[i], smaps, err) < 0) {
        goto fail;
      }
      break;
    default:
      continue;
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}


int
enqueue_children(elf_data_t *elf, Dwarf_Die die, std::deque<Dwarf_Die> *Q, char const **err)
{
  int ret;
  Dwarf_Error dwerr;
  Dwarf_Die child_die;

  Q->push_back(Dwarf_Die());
  ret = dwarf_child(die, &Q->back(), &dwerr);
  if(ret == DW_DLV_ERROR) {
    (*err) = "failed to read DWARF debugging entry (2)";
    Q->pop_back();
    return -1;
  } else if(ret == DW_DLV_NO_ENTRY) {
    Q->pop_back();
    return 0;
  }

  while(1) {
    child_die = Q->back();
    Q->push_back(Dwarf_Die());
    ret = dwarf_siblingof(elf->dwarf, child_die, &Q->back(), &dwerr);
    if(ret == DW_DLV_ERROR) {
      (*err) = "failed to read DWARF debugging entry (3)";
      Q->pop_back();
      return -1;
    } else if(ret == DW_DLV_NO_ENTRY) {
      Q->pop_back();
      break;
    }
  }

  return 0;
}


bool
sort_dwarf_funcs(Dwarf_Die d, Dwarf_Die e)
{
  Dwarf_Error dwerr;
  Dwarf_Attribute a;
  bool b, c;

  b = (dwarf_attr(d, DW_AT_MIPS_linkage_name, &a, &dwerr) == DW_DLV_OK) || (dwarf_attr(d, DW_AT_linkage_name, &a, &dwerr) == DW_DLV_OK);
  c = (dwarf_attr(e, DW_AT_MIPS_linkage_name, &a, &dwerr) == DW_DLV_OK) || (dwarf_attr(e, DW_AT_linkage_name, &a, &dwerr) == DW_DLV_OK);

  if(b && !c) return true;

  return false;
}


int
parse_cu_section_maps(elf_data_t *elf, 
                      std::vector<section_map_t> *smaps, std::vector<function_t> *funcs, 
                      char const **err)
{
  int ret;
  Dwarf_Error dwerr;
  Dwarf_Half tag;
  Dwarf_Die cu_die, child_die;
  std::deque<Dwarf_Die> Q;

  if(dwarf_siblingof(elf->dwarf, NULL, &cu_die, &dwerr) != DW_DLV_OK) {
    (*err) = "failed to read DWARF debugging entry (4)";
    goto fail;
  }

  /* source <-> instruction mapping */
  if(parse_dwarf_cu_die(elf, cu_die, smaps, err) < 0) {
    goto fail;
  }

  if(enqueue_children(elf, cu_die, &Q, err) < 0) {
    goto fail;
  }
  verbose(3, "parse_cu_section_maps: enqueued %zu dwarf entries", Q.size());

  /* ensure that functions with mangled names are handled first
   * (important for function signature parsing) */
  std::sort(Q.begin(), Q.end(), sort_dwarf_funcs);

  while(!Q.empty()) {
    child_die = Q.front();
    Q.pop_front();

    ret = dwarf_tag(child_die, &tag, &dwerr);
    if(ret != DW_DLV_OK) {
      (*err) = "failed to read DWARF DIE tag";
      goto fail;
    }

    switch(tag) {
    /* function (code) debugging entry */
    case DW_TAG_subprogram:
      verbose(3, "parse_cu_section_maps: DW_TAG_subprogram");
      if(parse_dwarf_func_ins(elf, child_die, smaps, err) < 0) {
        goto fail;
      }
      if(!have_llvminfo && (elf->dwarf_version < DWARF_FUNC_SIG_MIN_VERSION)) {
        print_warn("need at least " DWARF_FUNC_SIG_MIN_VERSION_STRING " to parse function signatures");
      } else if(!skip_func_sigs) {
        if(parse_dwarf_func_sig(elf, child_die, smaps, funcs, err) < 0) {
          goto fail;
        }
      }
      /* enqueue children of function (there are likely data entries there) */
      if(enqueue_children(elf, child_die, &Q, err) < 0) {
        goto fail;
      }
      break;

    /* data-related debugging entry */
    case DW_TAG_constant:
    case DW_TAG_variable:
#if 0
      verbose(3, "parse_cu_section_maps: DW_TAG_constant/DW_TAG_variable");
      if(parse_dwarf_data_die(elf, child_die, smaps, err) < 0) {
        goto fail;
      }
#endif
      break;

    default:
      break;
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}


int
parse_function_addrs_by_line(elf_data_t *elf, std::vector<function_t> *funcs, char const **err)
{
  int ret;
  char *lnsrc;
  char lnsrc_real[PATH_MAX];
  size_t i;
  function_t *fn;
  std::map<unsigned, std::vector<function_t*> > line2func;
  Dwarf_Error dwerr;
  Dwarf_Die cu_die;
  Dwarf_Line *srclines;
  Dwarf_Signed j, nsrclines;
  Dwarf_Unsigned lineno;
  Dwarf_Addr addr;

  srclines = NULL;

  /* fast lookup table for scalability */
  for(i = 0; i < funcs->size(); i++) {
    fn = &funcs->at(i);
    for(auto &kv : fn->line2addr) line2func[kv.first].push_back(fn);
  }

  if(dwarf_siblingof(elf->dwarf, NULL, &cu_die, &dwerr) != DW_DLV_OK) {
    (*err) = "failed to read DWARF debugging entry (5)";
    goto fail;
  }

  if(dwarf_srclines(cu_die, &srclines, &nsrclines, &dwerr) != DW_DLV_OK) {
    (*err) = "failed to get DWARF line information";
    goto fail;
  }

  for(j = 0; j < nsrclines; j++) {
    if(dwarf_lineno(srclines[j], &lineno, &dwerr) != DW_DLV_OK) {
      (*err) = "failed to get DWARF line number information";
      goto fail;
    }
    if(dwarf_lineaddr(srclines[j], &addr, &dwerr) != DW_DLV_OK) {
      (*err) = "failed to get DWARF line to instruction mapping";
      goto fail;
    }
    if(dwarf_linesrc(srclines[j], &lnsrc, &dwerr) != DW_DLV_OK) {
      (*err) = "failed to get DWARF line source file";
      goto fail;
    }

    if(!realpath(lnsrc, lnsrc_real)) {
      continue;
    }

    if(line2func[lineno].empty()) continue;
    for(i = 0; i < line2func[lineno].size(); i++) {
      fn = line2func[lineno][i];
      if(fn->cu_path.empty())                     continue;
      if(strcmp(fn->cu_path.c_str(), lnsrc_real)) continue;
      fn->line2addr[lineno] = addr;
      fn->addr2line[addr]   = lineno;
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(srclines) {
    dwarf_srclines_dealloc(elf->dwarf, srclines, nsrclines);
  }

  return ret;
}


int
parse_section_maps(elf_data_t *elf, std::vector<section_map_t> *smaps, 
                   std::vector<function_t> *funcs, char const **err)
{
  int ret;
  size_t n;
  Dwarf_Error dwerr;
  Dwarf_Unsigned cu_len, cu_next_off;
  Dwarf_Half cu_version, cu_ptr_size;
  Dwarf_Off cu_abbrv_off;

  ret = dwarf_elf_init(elf->e, DW_DLC_READ, NULL, NULL, &elf->dwarf, &dwerr);
  if(ret != DW_DLV_OK) {
    if(ret == DW_DLV_NO_ENTRY) {
      print_warn("no DWARF information found");
    } else {
      (*err) = "failed to initialize libdwarf";
      goto fail;
    }
  }

  n = 0;
  while(1) {
    ret = dwarf_next_cu_header(elf->dwarf, &cu_len, &cu_version, &cu_abbrv_off, &cu_ptr_size, &cu_next_off, &dwerr);
    if(ret == DW_DLV_ERROR) {
      (*err) = "failed to read DWARF compilation unit header";
      goto fail;
    } else if(ret == DW_DLV_NO_ENTRY) {
      verbose(3, "parse_section_maps: no more cu headers");
      break;
    }

    /* give it our best shot with unsupported DWARF versions, but things may not work as expected */
    if(cu_version < DWARF_MIN_VERSION) {
      print_warn("compilation unit with outdated DWARF version (older than " DWARF_MIN_VERSION_STRING ")");
    } else if(cu_version > DWARF_MAX_VERSION) {
      print_warn("compilation unit with unsupported DWARF version (newer than " DWARF_MAX_VERSION_STRING ")");
    }

    elf->dwarf_version = cu_version;
    verbose(3, "parse_section_maps: handling cu with DWARF version %u", cu_version);
    if(parse_cu_section_maps(elf, smaps, funcs, err) < 0) {
      goto fail;
    }
    if(parse_function_addrs_by_line(elf, funcs, err) < 0) {
      goto fail;
    }
    n++;
  }
  if(!n) {
    print_warn("no DWARF information found");
  }

  verbose(2, "");

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(elf->dwarf) {
    dwarf_finish(elf->dwarf, &dwerr);
    elf->dwarf = NULL;
  }

  return ret;
}


int
safe_disasm_entry_point(elf_data_t *elf, std::vector<section_map_t> *smaps, char const **err)
{
  /*
   * Mark ELF entry point and use it as a disassembly starting point.
   */

  int ret;
  btype *b;

  if(!elf->entry) {
    (*err) = "cannot find ELF entry point";
    goto fail;
  }
  //printf("DEBUG17\n");
  b = btype_by_addr(smaps, elf->entry);
  if(!b) {
    (*err) = "ELF entry point is outside selected sections";
    goto fail;
  }
  verbose(2, "marking ELF entry point at 0x%jx", elf->entry);
  //printf("DEBUG18\n");
  //printf("/n 2.marking function start :: 0x%jx  \n", elf->entry);
  globalFuncStarts.insert(elf->entry);
  //printf("DEBUG19\n");
  globalFuncStartsVect.push_back(elf->entry);
  //printf("DEBUG20\n");
  b->mark(MAP_FLAG_T, MAP_FLAG_T, MAP_FLAG_T, MAP_FLAG_T, b->funcend, b->cflow, b->call, MAP_FLAG_T, b->nop);
  //printf("DEBUG21\n");
  /* let's see how much of the binary we can conservatively reach from the entry point */
  if(safe_disasm(elf, smaps, elf->entry, err) < 0) {
    goto fail;
  }
  //printf("DEBUG22\n");
  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}


int
safe_disasm_symbols(elf_data_t *elf, std::vector<section_map_t> *smaps, std::vector<symbol_t> *syms, char const **err)
{
  /* 
   * Disassemble/mark functions and data pointed to by symbols, if available.
   */

  int ret; 
  size_t i, j;
  btype *b;
  symbol_t *sym;

  for(i = 0; i < syms->size(); i++) {
    sym = &syms->at(i);
    b = btype_by_addr(smaps, sym->value);
    if(!b && (sym->type == SYM_TYPE_FUNC)) {
      (*err) = "FUNC symbol points outside selected sections";
      goto fail;
    } else if(!b) {
      /* just ignore data symbols which point outside the PROGBITS sections */
      continue;
    }

    if(sym->type == SYM_TYPE_FUNC) {
      verbose(2, "marking function %s pointed to by FUNC symbol at 0x%jx", sym->name.c_str(), sym->value);
      //printf("/n 3.marking function start :: 0x%jx  \n", sym->value);
      b->mark(MAP_FLAG_T, MAP_FLAG_T, MAP_FLAG_T, MAP_FLAG_T, b->funcend, b->cflow, b->call, b->progentry, b->nop);
      globalFuncStarts.insert(sym->value);
      globalFuncStartsVect.push_back(sym->value);
      if(safe_disasm(elf, smaps, sym->value, err) < 0) {
        goto fail;
      }
    } else {
      verbose(2, "marking data object %s pointed to by symbol at 0x%jx (%ju bytes)", sym->name.c_str(), sym->value, sym->size);
      for(j = sym->value; j < (sym->value+sym->size); j++) {
        b = btype_by_addr(smaps, j);
        if(!b) {
          break;
        }
        b->mark(MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F, MAP_FLAG_F);
      }
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}


int
safe_disasm_ctors(elf_data_t *elf, std::vector<section_map_t> *smaps, char const **err)
{
  /* 
   * .ctors, .dtors, and .init_array (if present) contain arrays of code pointers which
   * we can use as starting points for disassembly.
   */

  int ret;
  btype *b;
  size_t i, len, ptrsize;
  uint64_t addr, ptr;
  section_map_t *s;

  ptrsize = elf->bits/8;
  for(i = 0; i < smaps->size(); i++) {
    s = &smaps->at(i);
    if(s->name == ".ctors" || s->name == ".dtors" || s->name == ".init_array") {
      for(addr = s->addr; addr < (s->addr+s->size); addr += ptrsize) {
        len = ptrsize;
        if(read_elf_section_by_addr(elf, smaps, addr, (uint8_t*)&ptr, &len, err) < 0) {
          goto fail;
        }
        if(len != ptrsize) {
          print_warn("skipping incomplete pointer in section %s", s->name.c_str());
          continue;
        }

        b = btype_by_addr(smaps, ptr);
        if(!b || !ptr) {
          /* the first and last pointers are delimiters which we should skip */
          continue;
        }
        verbose(2, "marking %s pointer at 0x%jx", s->name.c_str(), ptr);
	printf("/n 4.marking function start :: 0x%jx  \n",  ptr);
        b->mark(MAP_FLAG_T, MAP_FLAG_T, MAP_FLAG_T, MAP_FLAG_T, b->funcend, b->cflow, b->call, b->progentry, b->nop);
	globalFuncStarts.insert(ptr);
	globalFuncStartsVect.push_back(ptr);
        if(safe_disasm(elf, smaps, ptr, err) < 0) {
          goto fail;
        }
      }
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}


int
init_section_maps(elf_data_t *elf, std::vector<section_map_t> *smaps, char const **err)
{
  /*
   * Initialize section maps with suspected code/data markers based on section
   * read/write/execute flags. The maps are later refined.
   */

  size_t i, j;
  map_flag_t code;

  for(i = 0; i < smaps->size(); i++) {
    smaps->at(i).map.push_back(
      map_range_t(smaps->at(i).addr, smaps->at(i).size)
    );
    for(j = 0; j < smaps->at(i).size; j++) {
      if(smaps->at(i).flags & SEC_FLAG_EXEC) {
        code = MAP_FLAG_t;
      } else {
        code = MAP_FLAG_F;
      }
      smaps->at(i).map[0].btypes.push_back(btype_t(code));
    }
  }

  return 0;
}


int
parse_symbols(elf_data_t *elf, GElf_Shdr *shdr, std::vector<section_map_t> *smaps, std::vector<symbol_t> *syms, char const **err)
{
  int ret;
  uint64_t link;
  size_t i, len, strtab_len, symtab_len, nsym, n;
  Elf_Scn *scn;
  GElf_Shdr strtab_shdr;
  char *strtab_buf, *symname;
  uint8_t *symtab_buf;
  GElf_Sym sym;
  Elf32_Sym *sym32;
  Elf64_Sym *sym64;


  strtab_buf = NULL;
  symtab_buf = NULL;

  link = shdr->sh_link;
  len  = shdr->sh_size;
  nsym = (elf->bits == 64) ? len/sizeof(Elf64_Sym) : len/sizeof(Elf32_Sym);

  scn = elf_getscn(elf->e, link);
  if(!scn) {
    (*err) = "failed to get strtab section";
    goto fail;
  }
  if(!gelf_getshdr(scn, &strtab_shdr)) {
    (*err) = "failed to get strtab section header";
    goto fail;
  }

  strtab_len = strtab_shdr.sh_size;
  strtab_buf = (char*)malloc(strtab_len);
  if(!strtab_buf) {
    (*err) = "out of memory";
    goto fail;
  }
  n = strtab_len;
  if(read_elf_section_by_off(elf, strtab_shdr.sh_offset, (uint8_t*)strtab_buf, &n, err) < 0) {
    goto fail;
  } else if(n != strtab_len) {
    (*err) = "error while reading strtab";
    goto fail;
  }

  symtab_len = shdr->sh_size;
  symtab_buf = (uint8_t*)malloc(symtab_len);
  if(!symtab_buf) {
    (*err) = "out of memory";
    goto fail;
  }
  n = symtab_len;
  if(read_elf_section_by_off(elf, shdr->sh_offset, symtab_buf, &n, err) < 0) {
    goto fail;
  } else if(n != symtab_len) {
    (*err) = "error while reading symtab";
    goto fail;
  }

  for(i = 0; i < nsym; i++) {
    if(elf->bits == 64) {
      sym64 = (Elf64_Sym*)(symtab_buf+(i*sizeof(Elf64_Sym)));
      symname = (strtab_buf+sym64->st_name);
      sym.st_name  = sym64->st_name;
      sym.st_value = sym64->st_value;
      sym.st_size  = sym64->st_size;
      sym.st_info  = sym64->st_info;
    } else {
      sym32 = (Elf32_Sym*)(symtab_buf+(i*sizeof(Elf32_Sym)));
      symname = (strtab_buf+sym32->st_name);
      sym.st_name  = sym32->st_name;
      sym.st_value = sym32->st_value;
      sym.st_size  = sym32->st_size;
      sym.st_info  = sym32->st_info;
    }

    switch(GELF_ST_TYPE(sym.st_info)) {
    case STT_FUNC:
      if(sym.st_value > 0) {
        verbose(2, "marking FUNC symbol %s at 0x%jx", symname, sym.st_value);
        syms->push_back(symbol_t(SYM_TYPE_FUNC, symname, sym.st_value, sym.st_size));
      }
      break;
    case STT_OBJECT:
      if((sym.st_value > 0) && (sym.st_size > 0)) {
        verbose(2, "marking OBJECT symbol %s at 0x%jx (%ju bytes)", symname, sym.st_value, sym.st_size);
        syms->push_back(symbol_t(SYM_TYPE_OBJECT, symname, sym.st_value, sym.st_size));
      }
      break;
    case STT_TLS:
      if((sym.st_value > 0) && (sym.st_size > 0)) {
        verbose(2, "marking TLS symbol %s at 0x%jx (%ju bytes)", symname, sym.st_value, sym.st_size);
        syms->push_back(symbol_t(SYM_TYPE_TLS, symname, sym.st_value, sym.st_size));
      }
      break;
    /*case STT_NUM:*/
    case STT_COMMON:
    case STT_NOTYPE:
    case STT_SECTION:
    case STT_FILE:
    case STT_LOOS:
    case STT_HIOS:
    case STT_LOPROC:
    case STT_HIPROC:
      break;
    default:
      break;
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(strtab_buf) {
    free(strtab_buf);
  }
  if(symtab_buf) {
    free(symtab_buf);
  }

  return ret;
}


int
parse_section_headers(elf_data_t *elf, std::vector<section_map_t> *smaps, std::vector<symbol_t> *syms, char const **err)
{
  /*
   * Get basic information about the interesting sections in the ELF binary
   * (i.e., the PROGBITS sections). Also collect symbols if present.
   */

  int ret;
  char *secname;
  Elf_Scn *scn;
  GElf_Shdr shdr;
  size_t i, shstrndx;
  if(elf_getshdrstrndx(elf->e, &shstrndx) < 0) {
    (*err) = "failed to get section name strtab index";
    goto fail;
  }
  scn = NULL;
  while((scn = elf_nextscn(elf->e, scn))) {
    i = elf_ndxscn(scn);

    if(!gelf_getshdr(scn, &shdr)) {
      (*err) = "failed to get section header";
      goto fail;
    }

    if(!(secname = elf_strptr(elf->e, shstrndx, shdr.sh_name))) {
      (*err) = "failed to get section name";
      goto fail;
    }
    switch(shdr.sh_type) {
    case SHT_SYMTAB: //original
    //case SHT_DYNSYM: // XXX: dynsym contents also appear in the symtab 
      if(!strcmp(secname, ".dynsym")) continue;
      if(parse_symbols(elf, &shdr, smaps, syms, err) < 0) {
        goto fail;
      }
      continue;
    case SHT_PROGBITS:
      if(!shdr.sh_addr) {
        print_warn("skipping PROGBITS section %s at addr 0", secname);
        continue;
      }
      smaps->push_back(section_map_t());
      smaps->back().type = SEC_TYPE_PROGBITS;
      break;

    default:
      continue;
    }
    smaps->back().index = i;
    smaps->back().name  = std::string(secname);
    smaps->back().flags = SEC_FLAG_READ 
                            | ((shdr.sh_flags & SHF_WRITE) ? SEC_FLAG_WRITE : 0) 
                            | ((shdr.sh_flags & SHF_EXECINSTR) ? SEC_FLAG_EXEC : 0);
    smaps->back().off   = shdr.sh_offset;
    smaps->back().addr  = shdr.sh_addr;
    smaps->back().size  = shdr.sh_size;
  }

  /* Move .text section to the front of the vector for optimization
   * (it needs to be looked up most often) */
  for(i = 1; i < smaps->size(); i++) {
    if(smaps->at(i).name == ".text") {
      verbose(2, "moving section %zu (.text) to front of list", i);
      iter_swap(smaps->begin(), smaps->begin()+i);
      break;
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}


int
detect_overlapping_blocks(elf_data_t *elf, std::vector<function_t> *funcs, 
                          std::vector<overlapping_bb_t> *overlaps, char const **err)
{
  size_t i, j;
  function_t *f, *g;

  for(i = 0; i < funcs->size(); i++) {
    f = &funcs->at(i);
    if(f->inlined)         continue;
    if(f->cu_path.empty()) continue;
    for(j = (i+1); j < funcs->size(); j++) {
      g = &funcs->at(j);
      if(f == g)             continue;
      if(g->cu_path.empty()) continue;
      for(auto &kv : f->addr2line) {
        if(kv.first == 0) continue;
        if(g->addr2line.find(kv.first) == g->addr2line.end()) {
          continue;
        }
        if((f->cu_path == g->cu_path) && (f->addr2line[kv.first] == g->addr2line[kv.first])) continue;
        if((kv.first < f->base) || (kv.first >= (f->ranges[0].first + f->ranges[0].second))) continue;
        if((kv.first < g->base) || (kv.first >= (g->ranges[0].first + g->ranges[0].second))) continue;
        /* XXX: ignore overlaps where the two functions are exactly the same */
        if((f->ranges[0].first == g->ranges[0].first) && (f->ranges[0].second == g->ranges[0].second)) continue;
        /* found an overlap */
        overlaps->push_back(overlapping_bb_t());
        overlaps->back().addr = kv.first;
        overlaps->back().f    = f;
        overlaps->back().g    = g;
      }
    }
  }

  return 0;
}


char*
parse_llvminfo_preamble(char *line, unsigned minlen, std::string &modulepath, char const **err)
{
  char *tok;

  line = strchr(line, ' ');
 
  if(!line || (strlen(line) < minlen)) {
    (*err) = "bad line in llvm info file (parse_llvminfo_preamble, 1)";
    return NULL;
  }
  line++;

  tok = strchr(line, '\n');
  if(tok) (*tok) = '\0';

  tok = strchr(line, '\t');
  if(!tok) {
    (*err) = "bad line in llvm info file (parse_llvminfo_preamble, 2)";
    return NULL;
  }
  modulepath = std::string(line, tok-line);
  modulepath = str_realpath(modulepath);
  assert(!modulepath.empty());

  return line;
}


function_t*
parse_llvminfo_get_func(std::string &funcname, std::vector<function_t> *funcs)
{
  size_t i;
  char *demangled_;
  std::string demangled;
  function_t *fn;

  demangled_ = cplus_demangle(funcname.c_str(), DMGL_NO_OPTS);
  if(demangled_) demangled = std::string(demangled_);
  else demangled = funcname;

  fn = NULL;
  for(i = 0; i < funcs->size(); i++) {
    if(funcs->at(i).mangled_name == funcname) {
      fn = &funcs->at(i);
      break;
    }
  }
  if(!fn) {
    funcs->push_back(function_t(funcname, 0, 0));
    fn = &funcs->back();
  }

  return fn;
}


int
parse_llvminfo_callconv(char *line, std::vector<function_t> *funcs, char const **err)
{
  int ret;
  char *tok;
  std::string modulepath, funcname, callconv;
  function_t *fn;

  if(!(line = parse_llvminfo_preamble(line, 6, modulepath, err))) {
    goto fail;
  }
  tok = strchr(line, '\t');

  funcname = std::string(tok+1);
  funcname = funcname.substr(0, funcname.find_first_of('\t'));
  assert(!funcname.empty());
  tok = strchr(tok+1, '\t');
  if(!tok) {
    (*err) = "bad line in llvm info file (parse_llvminfo_callconv, 1)";
    goto fail;
  }
  callconv = std::string(tok+1);
  assert(!callconv.empty());

  verbose(3, "llvminfo_callconv: parsed line mod='%s' func='%s' callconv='%s'",
          modulepath.c_str(), funcname.c_str(), callconv.c_str());

  fn = parse_llvminfo_get_func(funcname, funcs);
  assert(fn);

  fn->cu_path  = modulepath;
  fn->callconv = callconv;

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}


int
parse_llvminfo_func_sig(char *line, std::vector<function_t> *funcs, char const **err)
{
  int ret;
  bool in_quotes;
  int in_parens, in_template;
  size_t n;
  char *tok, c;
  std::string modulepath, funcname, rettype, args, param, attributes, attr;
  function_t *fn;

  if(!(line = parse_llvminfo_preamble(line, 6, modulepath, err))) {
    goto fail;
  }
  tok = strchr(line, '\t');

  rettype = std::string(tok+1);
  rettype = rettype.substr(0, rettype.find_first_of('`'));
  rettype = rettype.substr(0, rettype.find_last_of(' '));
  assert(!rettype.empty());
  tok = strchr(tok+1, '`');
  if(!tok) {
    (*err) = "bad line in llvm info file (parse_llvminfo_func_sig, 1)";
    goto fail;
  }
  funcname = std::string(tok+1);
  funcname = funcname.substr(0, funcname.find_first_of('`'));
  assert(!funcname.empty());
 
  fn = parse_llvminfo_get_func(funcname, funcs);
  assert(fn);
  if(fn->valid_sig) {
    return 0;
  }

  fn->cu_path = modulepath;
  fn->ret = rettype;

  tok = strchr(tok+1, '`');
  if(tok) tok = strchr(tok+1, '(');
  if(!tok) {
    (*err) = "bad line in llvm info file (parse_llvminfo_func_sig, 2)";
    goto fail;
  }
  args = std::string(tok);
  n = args.find_last_of(')');
  if(n == std::string::npos) {
    (*err) = "bad line in llvm info file (parse_llvminfo_func_sig, 3)";
    goto fail;
  }
  args = args.substr(1, n-1);
  in_quotes   = false;
  in_parens   = 0;
  in_template = 0;
  for(n = 0; n < args.size(); n++) {
    c = args.at(n);
    if(in_quotes || in_parens || in_template || (c != ',')) {
      param.push_back(c);
    }

    if(c == '\"') {
      in_quotes = !in_quotes;
    } else if(c == '(') {
      in_parens++;
    } else if(c == ')') {
      in_parens--;
    } else if(c == '<') {
      in_template++;
    } else if(c == '>') {
      in_template--;
    }

    if((!in_quotes && !in_parens && !in_template && (c == ',')) || ((n+1) == args.size())) {
      boost::algorithm::trim(param);
      if(!param.empty()) fn->params.push_back(std::string(param));
      param.clear();
    }
  }
  fn->valid_sig = true;

  attributes = std::string(line);
  n = attributes.find_last_of(')');
  tok = (n == std::string::npos) ? NULL : &line[n];
  if(!tok) {
    (*err) = "bad line in llvm info file (parse_llvminfo_func_sig, 4)";
    goto fail;
  }
  tok++;

  while(tok && (*tok) && (strlen(tok) > 3)) {
    attr = std::string(tok+1);
    attr = attr.substr(0, attr.find_first_of(' '));
    assert(!attr.empty());
    fn->attributes.push_back(attr);
    if(attr == "nothrow") {
      fn->nothrow = true;
    } else if(attr == "noreturn") {
      fn->noret = true;
    } else if(attr == "icall") {
      fn->addrtaken = true;
    } else if(attr == "dead") {
      fn->dead = true;
    } else if(attr.find("multi-entry") != std::string::npos) {
      /* TODO: multi-entry(%u) */
    } else if(attr == "setjmp") {
      fn->multiret = true;
    } else {
      /* ignore */
    }
    tok = strchr(tok+1, ' ');
  }

  verbose(3, "llvminfo_func_sig: parsed line mod='%s' sig='%s %s(%s) %s'",
          modulepath.c_str(), rettype.c_str(), funcname.c_str(), 
          vecjoin(&fn->params, ", ").c_str(), vecjoin(&fn->attributes, " ").c_str());

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}


int
parse_llvminfo_func(char *line, std::vector<function_t> *funcs, char const **err)
{
  int ret;
  char *tok;
  size_t i;
  unsigned startline, endline;
  std::string modulepath, funcname;
  function_t *fn;

  if(!(line = parse_llvminfo_preamble(line, 8, modulepath, err))) {
    goto fail;
  }
  tok = strchr(line, '\t');

  startline = strtoul(tok+1, NULL, 0);
  tok = strchr(tok+1, '\t');
  if(!tok) {
    (*err) = "bad line in llvm info file (parse_llvminfo_func, 3)";
    goto fail;
  }
  endline = strtoul(tok+1, NULL, 0);
  tok = strchr(tok+1, '\t');
  if(!tok) {
    (*err) = "bad line in llvm info file (parse_llvminfo_func, 4)";
    goto fail;
  }
  assert(startline <= endline);
  funcname = std::string(tok+1);
  if(funcname.empty()) {
    print_err("parse_llvminfo_func: no function name (module=%s, start=%u, end=%u)",
              modulepath.c_str(), startline, endline);
  }
  assert(!funcname.empty());

  verbose(3, "llvminfo_func: parsed line mod='%s' func='%s' start='%u' end='%u'", 
          modulepath.c_str(), funcname.c_str(), startline, endline);

  fn = parse_llvminfo_get_func(funcname, funcs);
  assert(fn);

  fn->cu_path   = modulepath;
  fn->startline = startline;
  fn->endline   = endline;
  for(i = startline; i <= endline; i++) {
    fn->line2addr[i] = 0;
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}


int
parse_llvminfo_switch(char *line, std::vector<switch_t> *switches, char const **err)
{
  int ret;
  char *tok;
  unsigned startline, defaultline, caseline;
  std::string modulepath;
  switch_t *s;

  if(!(line = parse_llvminfo_preamble(line, 8, modulepath, err))) {
    goto fail;
  }
  tok = strchr(line, '\t');

  startline = strtoul(tok+1, NULL, 0);
  tok = strchr(tok+1, '\t');
  if(!tok) {
    (*err) = "bad line in llvm info file (parse_llvminfo_switch, 1)";
    goto fail;
  }
  defaultline = strtoul(tok+1, NULL, 0);
  tok = strchr(tok+1, '\t');
  if(!tok) {
    (*err) = "bad line in llvm info file (parse_llvminfo_switch, 2)";
    goto fail;
  }

  switches->push_back(switch_t());
  s = &switches->back();

  s->cu_path = modulepath;
  s->start_line = startline;
  s->default_line = defaultline;
  while(tok) {
    if((*(tok+1) >= '0') && (*(tok+1) <= '9')) {
      caseline = strtoul(tok+1, NULL, 0);
      s->case_lines.push_back(caseline);
    }
    tok = strchr(tok+1, ' ');
  }

  verbose(3, "llvminfo_switch: parsed line mod='%s' start='%u' default='%u'", 
          s->cu_path.c_str(), s->start_line, s->default_line);

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}


int
parse_llvminfo_addrtaken(char *line, std::vector<address_taken_bb_t> *at_blocks, char const **err)
{
  int ret;
  char *tok;
  std::string modulepath, funcname;
  unsigned startline, endline;
  address_taken_bb_t *at_bb;

  if(!(line = parse_llvminfo_preamble(line, 8, modulepath, err))) {
    goto fail;
  }
  tok = strchr(line, '\t');

  funcname = std::string(tok+1);
  funcname = funcname.substr(0, funcname.find_first_of('\t'));
  assert(!funcname.empty());
  tok = strchr(tok+1, '\t');
  if(!tok) {
    (*err) = "bad line in llvm info file (parse_llvminfo_addrtaken, 1)";
    goto fail;
  }

  startline = strtoul(tok+1, NULL, 0);
  tok = strchr(tok+1, '\t');
  if(!tok) {
    (*err) = "bad line in llvm info file (parse_llvminfo_addrtaken, 2)";
    goto fail;
  }
  endline = strtoul(tok+1, NULL, 0);
  assert(startline <= endline);

  at_blocks->push_back(address_taken_bb_t());
  at_bb = &at_blocks->back();

  at_bb->funcname = funcname;
  at_bb->cu_path = modulepath;
  at_bb->start_line = startline;
  at_bb->end_line = endline;

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}


int
parse_llvminfo(char *llvminfo_fname, std::vector<function_t> *funcs, 
               std::vector<switch_t> *switches, std::vector<address_taken_bb_t> *at_blocks, char const **err)
{
  int ret;
  FILE *f;
  char *linebuf, *tok;
  size_t buflen;

  f        = NULL;
  linebuf  = NULL;

  verbose(2, "parsing llvm info file '%s'", llvminfo_fname);
  f = fopen(llvminfo_fname, "r");
  if(!f) {
    (*err) = "failed to open llvm info file";
    goto fail;
  }

  buflen = 4096;
  linebuf = (char*)malloc(buflen);
  if(!linebuf) {
    (*err) = "out of memory";
    goto fail;
  }

  while(getline(&linebuf, &buflen, f) > 0) {
    if(strlen(linebuf) < 3) continue;
    if(linebuf[0] == '#') continue;
    tok = strchr(linebuf, '\n');
    if(tok) (*tok) = '\0';
    verbose(4, "parsing llvm info line '%s'", linebuf);
    if(!strncmp(linebuf, "CC", 2)) {
      if(parse_llvminfo_callconv(linebuf, funcs, err) < 0) goto fail;
    } else if(!strncmp(linebuf, "FS", 2)) {
      if(parse_llvminfo_func_sig(linebuf, funcs, err) < 0) goto fail;
    } else if(!strncmp(linebuf, "F", 1)) {
      if(parse_llvminfo_func(linebuf, funcs, err) < 0) goto fail;
    } else if(!strncmp(linebuf, "SW", 2)) {
      if(parse_llvminfo_switch(linebuf, switches, err) < 0) goto fail;
    } else if(!strncmp(linebuf, "AT", 2)) {
      if(parse_llvminfo_addrtaken(linebuf, at_blocks, err) < 0) goto fail;
    } else {
      continue;
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(f) {
    fclose(f);
  }
  if(linebuf) {
    free(linebuf);
  }

  return ret;
}


void
dump_btype(btype_t *b)
{
  if(!(b->code & 0x01)) {
    /* XXX: 'd'-16*(b->code & 0x02) == 'D' if the certain bit is set, 'd' otherwise */
    printf("%c", 'd'-16*(b->code & 0x02));
  } else {
    if(   !(b->insbound  & 0x01) && !(b->overlapping & 0x01)
       && !(b->bbstart   & 0x01) && !(b->funcstart   & 0x01) 
       && !(b->funcend   & 0x01) && !(b->cflow       & 0x01)
       && !(b->call      & 0x01) && !(b->progentry   & 0x01) && !(b->nop & 0x01)) {
      printf("%c", 'c'-16*(b->code & 0x02));
    } else {
      printf("[");
      printf("%c", 'c'-16*(b->code & 0x02));
      if(b->insbound    & 0x01) printf("%c", 'i'-16*(b->insbound    & 0x02));
      if(b->overlapping & 0x01) printf("%c", 'o'-16*(b->overlapping & 0x02));
      if(b->bbstart     & 0x01) printf("%c", 'b'-16*(b->bbstart     & 0x02));
      if(b->funcstart   & 0x01) printf("%c", 'f'-16*(b->funcstart   & 0x02));
      if(b->funcend     & 0x01) printf("%c", 'r'-16*(b->funcend     & 0x02));
      if(b->cflow       & 0x01) printf("%c", 'j'-16*(b->cflow       & 0x02));
      if(b->call        & 0x01) printf("%c", 'x'-16*(b->call        & 0x02));
      if(b->progentry   & 0x01) printf("%c", 'e'-16*(b->progentry   & 0x02));
      if(b->nop         & 0x01) printf("%c", 'n'-16*(b->nop         & 0x02));
      printf("]");
    }
  }
}


void
dump_section_maps(std::vector<section_map_t> *smaps)
{
  size_t i, j, k, n, c;

  //get each section and its size shaila nov13
  /*for(i = 0; i < smaps->size(); i++) 
  {
    printf("*************** map for section %s ***************\n", smaps->at(i).name.c_str());
    printf("<section %s, addr 0x%016jx, size %ju>\n", 
           smaps->at(i).name.c_str(), smaps->at(i).addr, smaps->at(i).size);
  }*/
  //get each section and its size


  for(i = 0; i < smaps->size(); i++) {
    printf("*************** map for section %s ***************\n", smaps->at(i).name.c_str());
    printf("<section %s, addr 0x%016jx, size %ju>\n", 
           smaps->at(i).name.c_str(), smaps->at(i).addr, smaps->at(i).size);
    if(!smaps->at(i).size) {
      printf("\n");
      continue;
    }
    n = 0;
    c = 0;
    for(j = 0; j < smaps->at(i).map.size(); j++) {
      printf("@0x%016jx: ", smaps->at(i).map[j].addr);
      for(k = 0; k < smaps->at(i).map[j].btypes.size(); k++) {
        if(k > 0 && ((((smaps->at(i).map[j].btypes[k].insbound & 0x01) || (smaps->at(i).map[j].btypes[k].overlapping & 0x01)) && map_show_insbounds) 
                     || (!(k % 16) && map_limit_16_bytes))) {
          printf("\n@0x%016jx: ", smaps->at(i).map[j].addr+k);
        }
        dump_btype(&smaps->at(i).map[j].btypes[k]);
        n++;
        if(smaps->at(i).map[j].btypes[k].code & 0x02) {
          c++;
        }
      }
      printf("\n");
    }
    printf("# %zu/%zu certain (%.2f%%)\n\n", c, n, ((double)c/n*100.0));
  }
}


void
dump_functions(std::vector<function_t> *funcs)
{
  size_t i, j;
  function_t *f;

  for(i = 0; i < funcs->size(); i++) {
    f = &funcs->at(i);
    if(!DUMP_PARTIAL_FUNCS && !f->valid_sig) continue;
    printf("F ");
    for(j = 0; j < f->ranges.size(); j++) {
      printf("0x%016jx %-6zu ", f->ranges[j].first, f->ranges[j].second);
    }
    printf("%-40s ", f->mangled_name.c_str());
    if(f->valid_sig) {
      printf("(..) [%s] %s%s(" , f->callconv.c_str(), f->inlined ? "inline " : "", f->ret.c_str());
      for(j = 0; j < f->params.size(); j++) {
        printf("%s%s", f->params[j].c_str(), ((j+1) < f->params.size()) ? ", " : "");
      }
      //printf(") "); //original
      printf(")   %d",f->params.size()); 
      for(j = 0; j < f->attributes.size(); j++) {
        printf("%s ", f->attributes[j].c_str());
      }
    }
    printf("\n");
  }
  printf("\n");
}


void
dump_switches(std::vector<switch_t> *switches, std::vector<function_t> *funcs)
{
  size_t i, j, k;
  switch_t *s;
  function_t *fn;

  for(i = 0; i < switches->size(); i++) {
    s = &switches->at(i);
    for(j = 0; j < funcs->size(); j++) {
      fn = &funcs->at(j);
      if(fn->cu_path != s->cu_path) continue;
      if(fn->startline > s->start_line) continue;
      if(fn->endline < s->start_line) continue;
 
      s->start_addr = fn->line2addr[s->start_line];
      s->default_addr = fn->line2addr[s->default_line];
      for(k = 0; k < s->case_lines.size(); k++) {
        s->case_addrs.push_back(fn->line2addr[s->case_lines[k]]);
      }
  
      break;
    }
    if(j < funcs->size()) {
      printf("SW+ %s\t%u (0x%jx)\t%u (0x%jx)\t", 
             s->cu_path.c_str(), s->start_line, s->start_addr, s->default_line, s->default_addr);
      for(j = 0; j < s->case_lines.size(); j++) {
        printf("%u (0x%jx) ", s->case_lines[j], s->case_addrs[j]);
      }
      printf("\n");
    } else {
      printf("SW- %s\t%u\t%u\t", s->cu_path.c_str(), s->start_line, s->default_line);
      for(j = 0; j < s->case_lines.size(); j++) {
        printf("%u ", s->case_lines[j]);
      }
      printf("\n");
    }
  }
  printf("\n");
}


void
dump_at_blocks(std::vector<address_taken_bb_t> *at_blocks, std::vector<function_t> *funcs)
{
  size_t i, j;
  address_taken_bb_t *at_bb;
  function_t *fn;

  for(i = 0; i < at_blocks->size(); i++) {
    at_bb = &at_blocks->at(i);
    for(j = 0; j < funcs->size(); j++) {
      fn = &funcs->at(j);
      if(fn->cu_path != at_bb->cu_path) continue;
      if(fn->startline > at_bb->start_line) continue;
      if(fn->endline < at_bb->end_line) continue;

      at_bb->start_addr = fn->line2addr[at_bb->start_line];
      at_bb->end_addr = fn->line2addr[at_bb->end_line];

      break;
    }
    assert(j < funcs->size());
    printf("AT %s\t%s\t%u (0x%jx)\t%u (0x%jx)\n",
           at_bb->cu_path.c_str(), at_bb->funcname.c_str(), 
           at_bb->start_line, at_bb->start_addr, at_bb->end_line, at_bb->end_addr);
  }
  printf("\n");
}


void
dump_overlapping_blocks(std::vector<overlapping_bb_t> *overlaps)
{
  size_t i;
  overlapping_bb_t *v;

  for(i = 0; i < overlaps->size(); i++) {
    v = &overlaps->at(i);
    printf("V 0x%016jx %s:%u %s <--> %s:%u %s\n", 
           v->addr, v->f->cu_path.c_str(), v->f->addr2line[v->addr], v->f->name.c_str(), 
                    v->g->cu_path.c_str(), v->g->addr2line[v->addr], v->g->name.c_str());
  }
  printf("\n");
}


void
dump_func_line_mapping_file(std::vector<function_t> *funcs, char *fname_prefix)
{
  FILE *f;
  std::string fname;
  size_t i;
  uint64_t addr;
  unsigned line;
  unsigned long color;
  function_t *fn;
  std::map<uint64_t, std::vector<std::pair<function_t*, unsigned> > > addrmap;
  char const *colors[] = { KRED, KGRN, KYEL, KBLU, KMAG, KCYN, KWHT };

  fname = std::string(fname_prefix) + "_func_mapping.txt";
  f = fopen(fname.c_str(), "w");
  if(!f) {
    print_err("cannot open file '%s' for writing", fname.c_str());
    return;
  }

  for(i = 0; i < funcs->size(); i++) {
    fn = &funcs->at(i);
    if(fn->line2addr.empty() || !fn->valid_sig) continue;
    for(auto &kv : fn->line2addr) {
      if(!kv.second) continue;
      if((kv.second < fn->base) || (kv.second >= (fn->ranges[0].first + fn->ranges[0].second))) continue;
      addrmap[kv.second].push_back(std::pair<function_t*, unsigned>(fn, kv.first));
    }
  }

  for(auto &kv : addrmap) {
    addr = kv.first;
    fprintf(f, KNRM "0x%jx %s", addr, (kv.second.size() > 1) ? "[overlap] " : "");
    for(i = 0; i < kv.second.size(); i++) {
      fn = kv.second[i].first;
      line = kv.second[i].second;
      color = hash_str_to_int(fn->name) % (sizeof(colors)/sizeof(*colors));
      fprintf(f, "%s%s%s:%u ", colors[color], fn->inlined ? "[inline] " : "", fn->name.c_str(), line);
    }
    fprintf(f, KNRM "\n");
  }

  fclose(f);
}


void
dump_func_line_mapping_graph(std::vector<function_t> *funcs, char *fname_prefix)
{
  FILE *f;
  std::string fname;
  size_t i, j;
  function_t *fn;
  std::set<uint64_t> addrs;

  fname = std::string(fname_prefix) + "_func_mapping.dot";
  f = fopen(fname.c_str(), "w");
  if(!f) {
    print_err("cannot open file '%s' for writing", fname.c_str());
    return;
  }

  fprintf(f, "digraph G {\n\n");

  /* create a line cluster for each function */
  for(i = 0; i < funcs->size(); i++) {
    fn = &funcs->at(i);
    if(fn->line2addr.size() == 0) continue;
    fprintf(f, "\tsubgraph cluster_f_%s {\n", fn->mangled_name.c_str());
    fprintf(f, "\t\tnode [style=filled];\n\t\t");
    j = 0;
    for(auto &kv : fn->line2addr) {
      fprintf(f, "%s_%u", hash_path(fn->cu_path).c_str(), kv.first);
      addrs.insert(kv.second);
      if((j+1) < fn->line2addr.size()) {
        fprintf(f, " -> ");
      } else {
        fprintf(f, ";\n");
      }
      j++;
    }
    fprintf(f, "\t\tlabel=\"%s\";\n", fn->mangled_name.c_str());
    fprintf(f, "\t\tcolor=lightgrey\n");
    fprintf(f, "\t}\n\n");
  }

  /* create an address cluster for the binary address space */
  fprintf(f, "\tsubgraph cluster_addrspace {\n");
  fprintf(f, "\t\tnode [style=filled];\n\t\t");
  j = 0;
  for(auto &a : addrs) {
    fprintf(f, "x%jx", a);
    if((j+1) < addrs.size()) {
      fprintf(f, " -> ");
    } else {
      fprintf(f, ";\n");
    }
    j++;
  }
  fprintf(f, "\t\tlabel=\"address space\";\n");
  fprintf(f, "\t\tcolor=lightgrey\n");
  fprintf(f, "\t}\n\n");

  /* link function lines to address space */
  for(i = 0; i < funcs->size(); i++) {
    fn = &funcs->at(i);
    if(fn->line2addr.size() == 0) continue;
    for(auto &kv : fn->line2addr) {
      if(kv.second == 0) continue;
      fprintf(f, "\t%s_%u -> x%jx;\n", hash_path(fn->cu_path).c_str(), kv.first, kv.second);
    }
  }

  fprintf(f, "\n}\n");

  fclose(f);
}


bool
sort_funcs_by_name(function_t f, function_t g)
{
  if(f.base && !g.base) return true;
  else if(!f.base && g.base) return false;
  else if(!f.line2addr.empty() &&  g.line2addr.empty()) return true;
  else if( f.line2addr.empty() && !g.line2addr.empty()) return false;
  else return (f.name < g.name);
}


void
print_usage(char *prog)
{
  printf(ELFMAP_VERSION"\n");
  printf(ELFMAP_CREDITS"\n");
  printf("\n%s [-vwhjRpsSOixdEBFlfg] -e <elf>\n", prog);
  printf("  -e : target ELF binary (must be x86 or x86-64)\n");
  printf("  -l <llvm info file>\n");
  printf("     : use auxiliary info from llvm\n");
  printf("  -B : list overlapping basic blocks after the code map (requires llvm info)\n");
  printf("  -F : list functions (and if applicable, their switches and AT blocks) after the code map\n");
  printf("  -E : assume functions are entered at their lowest address\n");
  printf("       (ignored if better entry point data is available from DWARF)\n");
  printf("  -j : don't follow fallthrough for conditional jumps; this option is\n");
  printf("       needed if there may be opaque predicates\n");
  printf("       (fallthroughs for unconditional jumps are never taken)\n");
  printf("  -R : assume return to the instruction following a call\n");
  printf("  -p : don't try to mark function/basic block padding bytes\n");
  printf("  -s : don't try to parse function signatures from DWARF info\n");
  printf("  -S : scan symbols only, ignoring DWARF\n");
  printf("  -O : allow overlapping instructions\n");
  printf("  -i : insert linebreak in map at each instruction boundary\n");
  printf("  -x : insert linebreak in map after every 16 bytes\n");
  printf("  -d <style>\n");
  printf("     : function name demangling style (as defined in demangle.h)\n");
  printf("  -f <file>\n");
  printf("     : dump auxiliary output files (function mapping, overlaps, ...)\n");
  printf("  -g <file>\n");
  printf("     : dump graphs of the results\n");
  printf("  -v : verbose\n");
  printf("  -w : disable warnings\n");
  printf("  -h : help\n");
  printf("The following is a good default config:\n");
  printf("  ./elfmap -iwRFEB -l <llvminfo> -e <elf> > <map>\n");
  printf("\n");
}


int
main(int argc, char *argv[])
{
  /*
   * Dump a map file for the given ELF binary that describes the type of each
   * byte in the PROGBITS sections (lower letters denote suspected type, while
   * their uppercase equivalents denote confirmed types):
   *
   *   d - data
   *   c - code
   *   i - instruction boundary
   *     Note that if a byte is an instruction boundary (start of an instruction),
   *     this implies that it is a code byte
   *   o - instruction boundary (start of overlapping instruction)
   *   b - basic block start
   *   f - function start
   *   e - program entry point (i.e., start of main)
   *   r - function end (return, tail call, etc.)
   *   j - control-flow instruction (jmp, call, ret, ...)
   *   x - crossref/call instruction
   *   n - NOP or other function padding
   *
   * The format of the map file is as follows:
   *
   *   @0x0100: ccc[CIFB]CCCC
   *   @0x0200: dddDDDDDDDDDD
   *
   * I.e., each line starts with the address of the first byte in that line,
   * followed by type descriptors for each byte. A byte with multiple type 
   * descriptors is delimited by square brackets. A new line start + address
   * indicator is mandatory if there is a gap in the address range. I.e., all
   * listed bytes are assumed to be sequential unless an address indicator
   * explicitly states otherwise. Address indicators may also be inserted every 
   * few bytes for human readability of the map file.
   *
   * The map files are based on DWARF and symbol information. As an extra refinement of 
   * the results, we run a recursive disassembly of each function and entry point found 
   * using DWARF/symbol data, parsing only guaranteed correct instructions (i.e., we stop 
   * for things like jump types where we're not 100% sure how to proceed). This provides 
   * a very conservative ground truth.
   */

  int elf_fd, opt, ret, archi;
  size_t i;
  char *elf_fname, *llvminfo_fname, *aux_fname, *graph_fname,*callInstTxt,*callPart,*instDetailTxt,*instPart,*funcPartTxt,*funcPart;
  //for file
  char *fileNameFunc;
  char *fileNameFunc2;
  FILE * fp;
  FILE * fp2;
  char * line = NULL;
  char line3[60];
  
  std::string str="";
  char** tokens;
  char *p;
  int colNo=0;
  //char line[30];
  size_t len = 0;
  ssize_t read;
  int posOfHexNum =0;
  char hexAdd[10]="";
  //char hexAdd[6];
  //for file
  char const *err;
  const char *sectype;
  char optstr[] = "vwhjRpsSOixd:EBFf:g:l:e:";
  elf_data_t elf;
  enum demangling_styles demangle_style;
  std::vector<section_map_t> smaps;
  std::vector<symbol_t> syms;
  std::vector<function_t> funcs;
  std::vector<switch_t> switches;
  std::vector<address_taken_bb_t> at_blocks;
  std::vector<overlapping_bb_t> overlaps;

  elf.e          = NULL;
  elf_fd         = -1;
  elf_fname      = NULL;
  llvminfo_fname = NULL;
  aux_fname      = NULL;
  graph_fname    = NULL;
  demangle_style = auto_demangling;

  opterr = 0;
  while((opt = getopt(argc, argv, optstr)) != -1) {
    switch(opt) {
    case 'v':
      verbosity++;
      break;

    case 'w':
      warnings = 0;
      break;

    case 'E':
      guess_func_entry = 1;
      break;

    case 'B':
      track_overlapping_blocks = 1;
      break;

    case 'F':
      track_funcs = 1;
      break;

    case 'j':
      ignore_fallthrough = 1;
      break;

    case 'R':
      guess_return = 1;
      break;

    case 'p':
      ignore_padding = 1;
      break;

    case 's':
      skip_func_sigs = 1;
      break;

    case 'S':
      symbols_only = 1;
      break;

    case 'O':
      allow_overlapping_ins = 1;
      break;

    case 'i':
      map_show_insbounds = 1;
      break;

    case 'x':
      map_limit_16_bytes = 1;

      break;

    case 'd':
      //demangle_style = cplus_demangle_name_to_style(optarg);
      fileNameFunc = strdup(optarg);
      printf("fileNameFunc:: %s  \n",fileNameFunc);
      //read the func addresses from the file
      /*fp = fopen(fileNameFunc, "r");
      if (fp == NULL)
      	exit(EXIT_FAILURE);
      while ((read = getline(&line, &len, fp)) != -1) 
      {
       //printf("line:: %s", line);
	
       for (int i = 2; i <  strlen(line); i++)
       {
      	 if (isalnum(line[i]))
         {
		//printf("\n%c", line[i]);
		hexAdd[i-2]=line[i];
	 }	
	 else
	 {	
		posOfHexNum = i-1;
		break;
	 }

       }
       //printf("\n%d",posOfHexNum);
       //printf("\n%s\n", hexAdd);
       posOfHexNum =0;
       //reading str as hex
       int num = (int)strtol(hexAdd, NULL, 16);       // number base 16
       //printf("%c\n", num);                         // print it as a char
       //printf("%d\n", num);                           // print it as decimal
       //printf("%X\n", num);                           // print it back as hex
       //funcStartAddSet.insert(num-16);		      //we set the start 20 instructions before identified func start
       //printf("funcStartAddSet.insert::%jx  ",num-16);
       funcStartAddSet.insert(num);		      //we set the start 20 instructions before identified func start
       //printf("funcStartAddSet.insert::%jx  ",num);
       //printf("funcStartAddSet.size()::%d  \n\n\n", funcStartAddSet.size());
      }
      fclose(fp);
      if (line)
        free(line);*/
      //read the func addresses from the file
      //reading the new file
      fileNameFunc = strdup(optarg);
      //fileNameFunc2 = "/home/shaila/Desktop/13thJune/Malware_3/Apexv4_Ghidra/ARM/stripped/Apex_arm03StripFuncIdentCombinedDATAAllFuncNew.csv";
      //fileNameFunc2 = fileNameFunc;
      fp2 = fopen(fileNameFunc, "r");
      if (fp2 == NULL)
      {	
	printf("cant open file...", line);
	exit(EXIT_FAILURE);
      }
      while ((read = getline(&line, &len, fp2)) != -1) 
      {
	char *line5 = new char[60];
	printf("line:: %s", line);
	strcpy(line3, line);
	strcpy(line5, line);
	printf("line3:: %s", line3);
	printf("line5:: %s", line5);
	printf("hexAdd::%s", hexAdd);
	p = strtok (line3,",/");
        while (p!= NULL)
  	{
		colNo++;
		if (colNo==2)
		{
			for (int i = 2; i <  strlen(p); i++)
       			{
			      	 if (isalnum(p[i]))
				 {
					hexAdd[i-2]=p[i];
					printf("\np[i]::%c  i::%d  strlen(p)::%d",p[i],i,strlen(p));
				 }	
				 else
				 {	
					posOfHexNum = i-1;
					break;
				 }
       			}
			//we must end the string
			hexAdd[strlen(p)-2]='\0';
			int num = (int)strtol(hexAdd, NULL, 16); 
			//mlAddDetails[num] =line5;
			mlAddDetails[num] = strtok(line5, "\n"); //we remove the \n at the back of the string
			printf("hexAdd::%s num::%X num::%d str::%s\n",hexAdd, num,num,mlAddDetails[num]);
			//printf("num::74280 num::74280 str::%s\n",mlAddDetails[74280]);
			funcStartAddSet.insert(num);
			
		}
		if (colNo>2)
			break;
		//printf ("p::%s\n",p);
    		p = strtok (NULL, ",");
  	}//while loop
	colNo=0;
	posOfHexNum =0;
	printf("fileNameFunc2:: %s  \n",fileNameFunc);

      }
      break;

    case 'f':
      aux_fname = strdup(optarg);
      break;

    case 'g':
      graph_fname = strdup(optarg);
      break;

    case 'e':
      elf_fname = strdup(optarg);
      printf("elf_fname:: %s  \n",elf_fname);
      callPart = "_callInst";
      callInstTxt = (char *) malloc(1 + strlen(elf_fname)+ strlen(callPart));
      strcpy(callInstTxt,elf_fname);
      strcat(callInstTxt,callPart);
      printf("callInstTxt:: %s  \n",callInstTxt);
      instPart = "_instCFGDetails";
      instDetailTxt = (char *) malloc(1 + strlen(elf_fname)+ strlen(instPart));
      strcpy(instDetailTxt,elf_fname);
      strcat(instDetailTxt,instPart);
      funcPart = "_DisTruthfuncBytes.csv";
      funcPartTxt = (char *) malloc(1 + strlen(elf_fname)+ strlen(funcPart));
      funcBytesInfoTxt = funcPartTxt;
      strcpy(funcPartTxt,elf_fname);
      strcat(funcPartTxt,funcPart);
      
      break;

    case 'l':
      have_llvminfo  = 1;
      llvminfo_fname = strdup(optarg);
      break;

    case 'h':
      break;
    default:
      print_usage(argv[0]);
      return 0;
    }
  }

  if(!elf_fname) {
    print_err("missing target elf (arg for -e)");
    goto fail;
  }
  if(track_overlapping_blocks && !llvminfo_fname) {
    print_err("overlapping basic block detection requires llvm info file");
    goto fail;
  }
  if(demangle_style == unknown_demangling) {
    print_err("unknown demangling style (arg for -d)");
    goto fail;
  }

  cplus_demangle_set_style(demangle_style);

  /* dump argument list for later reference in saved map files */
  printf("# ");
  for(opt = 0; opt < argc; opt++) {
    printf("%s ", argv[opt]);
  }
  printf("\n\n");

  verbose(1, "opening '%s'", elf_fname);
  elf_fd = open(elf_fname, O_RDONLY);
  if(elf_fd < 0) {
    print_err("failed to open '%s'", elf_fname);
    goto fail;
  }
  ret = open_elf(elf_fd, &elf, &err);
  if(ret < 0) {
    print_err("%s", err);
    goto fail;
  }
  //shaila: printing the machine archi
  printMacArchi(&elf, &err);
  //printf("DEBUG1\n");
  ret = parse_section_headers(&elf, &smaps, &syms, &err);
  if(ret < 0) {
    print_err("%s", err);
    goto fail;
  }
  verbose(2, "");

  verbose(1, "*************** interesting ELF sections ***************");
  verbose(1, "%-4s  %-20s %-10s %-5s %-18s %s", "idx", "name", "type", "flags", "addr", "size");
  for(i = 0; i < smaps.size(); i++) {
    verbose(1, "[%-2u]  %-20s %-10s %s%s%s   0x%016jx %ju", 
            i, smaps[i].name.c_str(), "PROGBITS",
            smaps[i].flags & SEC_FLAG_READ  ? "r" : "-",
            smaps[i].flags & SEC_FLAG_WRITE ? "w" : "-",
            smaps[i].flags & SEC_FLAG_EXEC  ? "x" : "-",
            smaps[i].addr, smaps[i].size);
  }
  verbose(1, "");

  ret = init_section_maps(&elf, &smaps, &err);
  if(ret < 0) {
    print_err("%s", err);
    goto fail;
  }
  //printf("DEBUG2\n");
  verbose(1, "*************** suspected section types ***************");
  for(i = 0; i < smaps.size(); i++) {
    if(smaps[i].map[0].btypes.empty()) {
      sectype = "none";
    } else {
      sectype = (smaps[i].map[0].btypes[0].code & 0x01) ? "code" : "data";
    }
    verbose(1, "[%-2u]  %-20s %s (%ju bytes)", 
            i, smaps[i].name.c_str(), sectype, smaps[i].map[0].btypes.size());
  }
  verbose(1, "");
  //printf("DEBUG3\n");
  //shaila nov 13
  /*for(i = 0; i < smaps->size(); i++) 
  {
    printf("*************** map for section %s ***************\n", smaps->at(i).name.c_str());
    printf("<section %s, addr 0x%016jx, size %ju>\n", 
           smaps->at(i).name.c_str(), smaps->at(i).addr, smaps->at(i).size);
  }*/
  for(i = 0; i < smaps.size(); i++) 
  {
    /*printf("*************** map for section %s ***************\n", smaps[i].name.c_str());
    printf("<section %s, addr 0x%016jx, size %ju>\n", 
           smaps[i].name.c_str(), smaps[i].addr, smaps[i].size);*/
   sectionStartsAdd[smaps[i].name.c_str()] = smaps[i].addr;
   sectionEndsAdd[smaps[i].name.c_str()]   = smaps[i].addr +  smaps[i].size;
   sectionSize[smaps[i].name.c_str()] = smaps[i].size;
  }
  /*printf("\n<section %s, start:: 0x%016jx, end:: 0x%016jx>", 
           ".text", sectionStartsAdd[".text"], sectionEndsAdd[".text"]);
  printf("\n<section %s, start:: 0x%016jx, end:: 0x%016jx>", 
           ".rodata", sectionStartsAdd[".rodata"], sectionEndsAdd[".rodata"]);*/
  //readROData(&elf, &smaps, 4426624, &err, 500);
  //this is to read the jump target addresses for mips architecture
  //if (sectionStartsAdd.count(".rodata"))
	//readROData(&elf, &smaps, sectionStartsAdd[".rodata"], &err, 500);
  	//readROData(&elf, &smaps, sectionStartsAdd[".rodata"], &err, sectionSize[".rodata"]);
  //shaila nov 13
  ret = safe_disasm_entry_point(&elf, &smaps, &err);
  if(ret < 0) {
    print_err("%s", err);
    goto fail;
  }
  //printf("DEBUG4\n");
  ret = safe_disasm_symbols(&elf, &smaps, &syms, &err);
  if(ret < 0) {
    print_err("%s", err);
    goto fail;
  }
  //printf("DEBUG5\n");
  if(track_funcs || track_overlapping_blocks) {
    for(i = 0; i < syms.size(); i++) {
      if(syms[i].type == SYM_TYPE_FUNC) {
        funcs.push_back(function_t(syms[i].name, syms[i].value, syms[i].size));
      }
    }
  }
  //printf("DEBUG6\n");
  if(have_llvminfo) {
    ret = parse_llvminfo(llvminfo_fname, &funcs, &switches, &at_blocks, &err);
    if(ret < 0) {
      print_err("%s", err);
      goto fail;
    }
  }
  //printf("DEBUG7\n");
  ret = safe_disasm_ctors(&elf, &smaps, &err);
  if(ret < 0) {
    print_err("%s", err);
    goto fail;
  }
  //printf("DEBUG8\n");
  if(!symbols_only) {
    ret = parse_section_maps(&elf, &smaps, &funcs, &err);
    if(ret < 0) {
      print_err("%s", err);
      goto fail;
    }
  }
  //printf("DEBUG9\n");
  //adding BBs for BAL instructions
  addBBForBALInst_MIPS_ins(&smaps);
  //printf("DEBUG10\n");
  //adding BBs for BAL instructions
  //adding mdt calls for tail calls for ARM
  markBFuncCalls(&smaps);
  //printf("DEBUG11\n");
  //adding mdt calls for tail calls for ARM
  std::sort(funcs.begin(), funcs.end(), sort_funcs_by_name);
  //printf("DEBUG12\n");
  dump_section_maps(&smaps);
  //printf("DEBUG13\n");
  if(track_funcs) {
    dump_functions(&funcs);
    dump_switches(&switches, &funcs);
    dump_at_blocks(&at_blocks, &funcs);
  }
  //printf("DEBUG14\n");
  if(track_overlapping_blocks) {
    if(detect_overlapping_blocks(&elf, &funcs, &overlaps, &err) < 0) {
      goto fail;
    }
    dump_overlapping_blocks(&overlaps);
  }
  //printf("DEBUG15\n");
  if(aux_fname) {
    dump_func_line_mapping_file(&funcs, aux_fname);
  }
  //printf("DEBUG16\n");
  if(graph_fname) {
    dump_func_line_mapping_graph(&funcs, graph_fname);
  }
  //print info about direct calls
  //printDirectCallins(&smaps,&callInstTxt);
  //print info about direct calls

  //print info about direct calls
  //printInstDetailsAndTargets(&smaps,&instDetailTxt);
  //print info about direct calls
  ret = 0;
  goto cleanup;

fail:
  ret = 1;

cleanup:
  close_elf(&elf);
  if(elf_fd >= 0) {
    close(elf_fd);
  }
  if(elf_fname) {
    free(elf_fname);
  }
  if(llvminfo_fname) {
    free(llvminfo_fname);
  }
  if(aux_fname) {
    free(aux_fname);
  }
  if(graph_fname) {
    free(graph_fname);
  }

  return ret;
}




