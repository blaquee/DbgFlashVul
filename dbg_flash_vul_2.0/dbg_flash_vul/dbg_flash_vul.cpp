//// my_windbg_ext.cpp : Defines the exported functions for the DLL application.
////
//
#include "stdafx.h"
//
#include <dbgeng.h> 
#pragma comment (lib ,"dbgeng.lib")

#include <Wdbgexts.h>
#include <string>
#include <map>
#include <vector>
#include <set>
#define  HOOKED_BYTES_SIZE 5
IDebugAdvanced2*  gAdvancedDebug2 = NULL;
IDebugControl4*   gDebugControl4 = NULL;
IDebugControl*    gExecuteCmd = NULL;
IDebugClient*     gDebugClient = NULL;

ULONG64 g_hooked_function_address = 0;
ULONG64 g_overwrite_address_in_hooked_func = 0;
const ULONG64 g_overwrite_offset = 0xC; //0x2B;
ULONG64 g_get_method_name_found_addr = 0;
ULONG64 g_gabbage_func_found_addr = 0;
ULONG_PTR g_base_address = 0x10000000;
bool g_hooked = false;
std::set<ULONG_PTR> g_method_ids_need_to_set_bp;
std::set<std::string> g_method_name_need_to_set_bp;
std::set<std::string> g_method_set;
ULONG64 g_last_jit_method_id = 0;
ULONG64 g_last_jit_code_addr = 0;
bool g_dump_method_info_detail = false;
bool g_dump_method_info_detail_ex = false;
char g_save_hooked_bytes[HOOKED_BYTES_SIZE] = {0};

/***********************************************************
 * Global Variable Needed For Versioning
 ***********************************************************/              
EXT_API_VERSION g_ExtApiVersion = {
         5 ,
         5 ,
         EXT_API_VERSION_NUMBER ,
         0
     } ;
/***********************************************************
 * ExtensionApiVersion
 *
 * Purpose: WINDBG will call this function to get the version
 *          of the API
 *
 *  Parameters:
 *     Void
 *
 *  Return Values:
 *     Pointer to a EXT_API_VERSION structure.
 *
 ***********************************************************/              
LPEXT_API_VERSION WDBGAPI ExtensionApiVersion (void)
{
    return &g_ExtApiVersion;
}


/***********************************************************
 * WinDbgExtensionDllInit
 *
 * Purpose: WINDBG will call this function to initialize
 *          the API
 *
 *  Parameters:
 *     Pointer to the API functions, Major Version, Minor Version
 *
 *  Return Values:
 *     Nothing
 *
 ***********************************************************/              
VOID WDBGAPI WinDbgExtensionDllInit (PWINDBG_EXTENSION_APIS 
           lpExtensionApis, USHORT usMajorVersion, 
           USHORT usMinorVersion)
{
     ExtensionApis = *lpExtensionApis;
     HRESULT hResult = S_FALSE;

     if (hResult = DebugCreate(__uuidof(IDebugClient), (void**) &gDebugClient) != S_OK)
     {
         dprintf("Acuqiring IDebugClient* Failled\n\n");
         return;
     }

     if (hResult = gDebugClient->QueryInterface(__uuidof(IDebugControl), (void**) &gExecuteCmd) != S_OK)
     {
         dprintf("Acuqiring IDebugControl* Failled\n\n");
         return;
     }

     if (hResult = gDebugClient->QueryInterface(__uuidof(IDebugAdvanced2), (void**) &gAdvancedDebug2) != S_OK)
     {
         dprintf("Acuqiring IDebugAdvanced2* Failled\n\n");
         return;
     }

     if (hResult = gDebugClient->QueryInterface(__uuidof(IDebugControl4), (void**) &gDebugControl4) != S_OK)
     {
         dprintf("Acuqiring IDebugControl4* Failled\n\n");
         return;
     }
     dprintf("load extension success, enter !help to get info. if need plz contact @heisecode\n");
}


/***********************************************************
 * Global Variable Needed For Functions
 ***********************************************************/              
WINDBG_EXTENSION_APIS ExtensionApis = {0};

/***********************************************************
 * !help
 *
 * Purpose: WINDBG will call this API when the user types !help
 *          
 *
 *  Parameters:
 *     N/A
 *
 *  Return Values:
 *     N/A
 *
 ***********************************************************/
DECLARE_API (help)
{
    dprintf("Set Jit Code breakpoint steps:\n");
    dprintf("\t 1> Use !SetBaseAddress <flashplayer base addreess>  to set base, default is 0x10000000\n");
    dprintf("\t 2> Use !SetBpForJitCode <AS3 method name>  to set breakpoint\n\n");

    dprintf("AS3 method name style in flash player internal is like this:\n");
    dprintf("\t 1> class member method: [package::class/method], example: a_pack::b_class/c_method\n");
    dprintf("\t 2> class constructor: [package::class], example: a_pack::b_class\n");
    dprintf("\t 3> class static method: [package::class$/method], example: a_pack::b_class$/c_static_method\n");
    dprintf("\t 4> if package name is empty then no 'package::' prefix\n");

    dprintf("Trace Jit Method:\n");
    dprintf("\t 1> !EnableTraceJit <0 or 1>, enable/disable trace jit method call\n");
    dprintf("\t 2> Trace all methods call may be added later....\n");
}

int HexCharToInt(char c) {
    if ( c >= '0' && c <= '9' ) {
        return c - '0';
    } else if ( c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if ( c >= 'A' && c <= 'F' ) {
        return c - 'A' + 10;
    }
    return -1;
}

unsigned HexDecode(char *inbuf, unsigned inLength, char *outbuf, unsigned outLength) {
    unsigned decodeLen = 0;
    if ( NULL == inbuf || NULL == outbuf || (inLength / 2) > outLength ) {
        return 0;
    }
    for ( unsigned i = 0; i < inLength - 1; i += 2 ) {
        int high = HexCharToInt( inbuf[i] );
        int low  = HexCharToInt( inbuf[i + 1] );
        if ( high != -1 && low != -1 ) {
            outbuf[ decodeLen ++ ] = low | (high << 4) ;
        } else {
            break;
        }
    }
    return decodeLen;
}


bool ExtExecuteCmd(const char* cmd) {
    if (gExecuteCmd->Execute(DEBUG_OUTCTL_THIS_CLIENT | DEBUG_OUTCTL_OVERRIDE_MASK | DEBUG_OUTCTL_NOT_LOGGED,
                                cmd,
                                DEBUG_EXECUTE_DEFAULT ) != S_OK)
    {
        dprintf("Executing %s failled\n", cmd);
        return false;
    }

    return true;
}

struct HookData {
    HookData() {
        data_ = 0;
        len_ = 0;
    }
    HookData(char* data, unsigned len) {
        data_ = data;
        len_ = len;
    }
    ~HookData() {
        //delete data_;
    }
    char* data_;
    unsigned len_;
};
std::map<unsigned, HookData> g_HookMap;

bool ExtHookAddress(unsigned addr, char* data, unsigned len) {
    //dprintf("Begin to hook 0x%08x \n", addr);
    if (g_HookMap.find(addr) != g_HookMap.end()) {
        dprintf("address is already hooked!\n");
        return true;
    }

    ULONG bytes_read = 0;
    HookData hook_data;
    hook_data.len_ = len;
    hook_data.data_ = new char[len];

    ReadMemory(addr, hook_data.data_, hook_data.len_, &bytes_read);
    if (bytes_read != len) {
        dprintf("cannot read memory, hook failed!\n");
        return false;
    }

    ULONG bytes_write = 0;
    WriteMemory(addr, data, len, &bytes_write);
    if (bytes_write != len) {
        dprintf("cannot write memory, hook failed!\n");
        return false;
    }

    g_HookMap[addr] = hook_data;

    return true;
}


bool ExtUnHookAddress(unsigned addr) {
    //dprintf("Begin to unhook 0x%08x \n", addr);
    std::map<unsigned, HookData>::iterator iter = g_HookMap.find(addr);
    if (iter == g_HookMap.end()) {
        dprintf("address is already unhooked!\n");
        return true;
    }

    HookData hook_data = iter->second;

    ULONG bytes_write = 0;
    WriteMemory(addr, hook_data.data_, hook_data.len_, &bytes_write);

    if (bytes_write != hook_data.len_) {
        dprintf("cannot write memory, unhook failed!\n");
        return false;
    }

    g_HookMap.erase(addr);

    return true;
}

bool ExtWriteMemory(char* hex_string, ULONG64 addr, PULONG64 hex_len) {
    ULONG len = strlen(hex_string);
    char* hex_bin = new char[len / 2];
    HexDecode(hex_string, len + 1, hex_bin, len / 2);
    ULONG bytes_write = 0;
    WriteMemory(addr, hex_bin, len / 2, &bytes_write);
    if (bytes_write != (len / 2)) {
        dprintf("write memory %s to 0x%08x failed\n", hex_string, addr);
        return false;
    }
    *hex_len = (len / 2);
    return true;
}

bool ExtAssemble(ULONG64 addr, std::vector<std::string>& instrs) {
    ULONG64 begin = addr;
    HRESULT ret;
    for (int i = 0; i < instrs.size(); ++i) {
        ret = gDebugControl4->Assemble(begin, instrs[i].c_str(), &begin);
        if (ret != S_OK) {
            dprintf("assemble address 0x%08x failed\n", begin);
            return false;
        }
    }

    return true;
}

bool ExtAssembleSingle(ULONG64 addr, std::string& instr, PULONG64 end_addr) {
    ULONG64 end = addr;
    
    HRESULT ret = gDebugControl4->Assemble(addr, instr.c_str(), &end);
    if (ret != S_OK) {
        dprintf("assemble address 0x%08x failed\n", addr);
        return false;
    }
    //dprintf("assemble address 0x%08x succed, end address is 0x%08x \n", addr, end);
    *end_addr = end;
    return true;
}

bool ExtMakeSetJitJmpInstr() {
    //dprintf("begin to make set jit jmp...\n");

    std::string instr = "jmp 0x";
    char jmp_offset[9] = {0};
    sprintf_s(jmp_offset, "%08x", g_gabbage_func_found_addr);
    instr += jmp_offset;
    ULONG64 end_addr = 0;
    return ExtAssembleSingle(g_overwrite_address_in_hooked_func, instr, &end_addr);
}

bool ExtMakeHookingFunc() {
    //dprintf("begin to make hooking func...\n");

    ULONG64 hook_addr = g_gabbage_func_found_addr;
	ULONG64 bytes_write = 0;

    // save hooked function instruction 5 bytes
	if(!WriteMemory(hook_addr, g_save_hooked_bytes, HOOKED_BYTES_SIZE, (PULONG)&bytes_write)) {
		return false;
	}
	hook_addr += bytes_write;

    // pushad
	if(!ExtWriteMemory("60", hook_addr, &bytes_write)) {
		return false;
	}
	hook_addr += bytes_write;

    //// mov ecx,esi
    //if(!ExtWriteMemory("8bce", hook_addr, &bytes_write)) {
    //    return false;
    //}
	// mov ecx,edi
	if(!ExtWriteMemory("8bcf", hook_addr, &bytes_write)) {
	    return false;
	}
    hook_addr += bytes_write;

    // call getMethodName
    std::string instr_3 = "call 0x";
    char call_offset[9] = {0};
    sprintf_s(call_offset, "%08x", g_get_method_name_found_addr);
    instr_3 += call_offset;
    //dprintf("call instr is %s\n", instr_3);
    if(!ExtAssembleSingle(hook_addr, instr_3, &hook_addr)) {
        return false;
    }

    // popad
    bytes_write = 0;
    if(!ExtWriteMemory("61", hook_addr, &bytes_write)) {
        return false;
    }
    hook_addr += bytes_write;

    // jump setJit
    std::string instr_5 = "jmp 0x";
    ULONG64 jmp_addr = g_overwrite_address_in_hooked_func + 5;
    char jmp_offset[9] = {0};
    sprintf_s(jmp_offset, "%08x", jmp_addr);
    instr_5 += jmp_offset;
    //dprintf("jmp instr is %s\n", instr_5);
    if(!ExtAssembleSingle(hook_addr, instr_5, &hook_addr)) {
        return false;
    }

    return true;
}

void ExtSearchMemory(ULONG64 base, ULONG64 range, PVOID pattern, PULONG64 found_addr) {
    char* cPattern = (char*)pattern;
    ULONG PatternLength = strlen(cPattern);
    char* uPattern = new char[PatternLength / 2];
    HexDecode(cPattern, PatternLength + 1, uPattern, PatternLength / 2);

    SearchMemory(base, range, PatternLength / 2, uPattern, found_addr);
    delete [] uPattern;
}

bool ExtSaveHookedBytes() {
	ULONG read_bytes = 0;
	ReadMemory(g_overwrite_address_in_hooked_func, g_save_hooked_bytes, HOOKED_BYTES_SIZE, &read_bytes);
	if (read_bytes != HOOKED_BYTES_SIZE) {
		dprintf("Save Hooked Bytes failed!\n");
		return false;
	}

	return true;
}

bool HookJit() {
    if (g_base_address == 0) {
        dprintf("Please input base address first!\n");
        return false;
    }
    if (g_hooked) {
        return true;
    }

	// find set jit function address
    char* cPattern = "8B4C2408568B7424088B463025FFFF7F";
	// find verifyMethod
	//char* cPattern = "81EC6C010000538B9C2478010000558B";
    ExtSearchMemory(g_base_address, 0x2000000, cPattern, &g_hooked_function_address);
    //dprintf("g_hooked_function_address is 0x%08x\n", g_hooked_function_address);
	g_overwrite_address_in_hooked_func = g_hooked_function_address + g_overwrite_offset;

	// find get method name address
    cPattern = "8B4110A801741383E0FE740C8B400C52";
    ExtSearchMemory(g_base_address, 0x2000000, cPattern, &g_get_method_name_found_addr);
    //dprintf("g_get_method_name_found_addr is 0x%08x\n", g_get_method_name_found_addr);

    //cPattern = "8B4C240432D2E8C5890700C20400";
    cPattern = "32D2E8C9FFFFFF8B4C240485C0741568";
    ExtSearchMemory(g_base_address, 0x2000000, cPattern, &g_gabbage_func_found_addr);
    //dprintf("g_gabbage_func_found_addr is 0x%08x\n", g_gabbage_func_found_addr);

	if (!ExtSaveHookedBytes()) {
		return false;
	}

    if (!ExtMakeHookingFunc()) {
        dprintf("make hooking func failed!\n");
        return false;
    }

    if (!ExtMakeSetJitJmpInstr()) {
        dprintf("make set jit jmp failed!\n");
        return false;
    }

    std::string bp_1 = "bu 0x";
    char bp1_addr[9] = {0};
    sprintf_s(bp1_addr, "%08x", g_gabbage_func_found_addr);
    bp_1 += bp1_addr;
    //char* output_method_id_jit_code_addr = "  \".echo ****; .printf \\\"method_id = 0x%x, jitcode = 0x%08x\\\", poi(esi+20) , ecx; !HandleHookId poi(esi+20); .echo; g\" ";
    char* output_method_id_jit_code_addr = "  \"!HandleHookId poi(esi+20); g\" ";
    bp_1 += output_method_id_jit_code_addr;
    if (!ExtExecuteCmd(bp_1.c_str())) {
        return false;
    }

    std::string bp_2 = "bu 0x";
    char bp2_addr[9] = {0};
    sprintf_s(bp2_addr, "%08x", g_gabbage_func_found_addr + 0xD);
    bp_2 += bp2_addr;
    //char* output_method_name = "  \".printf \\\"method_name = %ma, addr = %x\\\", poi(eax+8), poi(eax+8); !HandleHookName poi(eax+8); .echo; .echo ****; g\" ";
    char* output_method_name = "  \"!HandleHookName poi(eax+8); g\" ";
    bp_2 += output_method_name;
    if (!ExtExecuteCmd(bp_2.c_str())) {
        return false;
    }

    g_hooked = true;
    return true;
}

std::string ExtGetStringFromAddr(ULONG_PTR addr) {
    //dprintf("In ExtGetStringFromAddr, addr is %x\n", addr);
    std::string str;
    if (!addr) {
        return str;
    }
    char total[256] = {0};
    char* offset = total;

    
    bool flag = true;
    do {
        char buffer[8] = {0};
        ULONG bytes_read = 0;
        ReadMemory(addr, buffer, 8, &bytes_read);
        if (bytes_read != 8) {
            return str;
        }
        for (int i = 0; i < 8; ++i) {
            if (buffer[i] == 0) {
                //dprintf("In ExtGetStringFromAddr, read the null char\n");
                flag = false;
                strncpy_s(offset, 8, buffer, 8);
                break;
            }
        }

        if (flag) {
            memcpy(offset, buffer, 8);
            offset += 8;
        }
        addr += 8;

    } while (flag && (offset - total < 256));

    if (flag) {
        return str;
    }

    str = total;
    return str;
    
}

/***********************************************************
 * !HookJit
 *
 * Purpose: WINDBG will call this API when the user types !HookJit
 *          
 *
 *  Parameters:
 *     !HookJit <base address>
 *
 *  Return Values:
 *     N/A
 *
 ***********************************************************/
DECLARE_API (SetBaseAddress)
{
    ULONG_PTR base_address = GetExpression(args);
    //dprintf("base address is 0x%08x\n", base_address);
    if(!base_address)
    {
        dprintf("Please input flash player base address!\n");
        return;
    }
    g_base_address = base_address;
}

/***********************************************************
 * !SetIdBpForJitCode
 *
 * Purpose: WINDBG will call this API when the user types !SetIdBpForJitCode
 *          
 *
 *  Parameters:
 *     !SetIdBpForJitCode <method_id>
 *
 *  Return Values:
 *     N/A
 *
 ***********************************************************/
DECLARE_API (SetIdBpForJitCode)
{
    if (!HookJit()){
        return;
    }
    ULONG_PTR method_id = GetExpression(args);
    //dprintf("SetBpForJitCode method id is 0x%x\n", method_id);
    g_method_ids_need_to_set_bp.insert(method_id);
}

/***********************************************************
 * !SetBpForJitCode
 *
 * Purpose: WINDBG will call this API when the user types !SetBpForJitCode
 *          
 *
 *  Parameters:
 *     !SetBpForJitCode <method_name>
 *
 *  Return Values:
 *     N/A
 *
 ***********************************************************/
DECLARE_API (SetBpForJitCode)
{
    if (!HookJit()){
        return;
    }

    std::string method_name(args);
    g_method_name_need_to_set_bp.insert(method_name);
    //dprintf("SetBpForJitCode %s\n", args);
}

/***********************************************************
 * !HandleHookId
 *
 * Purpose: WINDBG will call this API when the user types !HandleHookBps
 *          
 *
 *  Parameters:
 *     !HandleHookId <method_id>
 *
 *  Return Values:
 *     N/A
 *
 ***********************************************************/
DECLARE_API (HandleHookId)
{
    ULONG_PTR method_id = GetExpression(args);
    g_last_jit_method_id = method_id;

    ULONG_PTR ecx_val = GetExpression("ecx");
    g_last_jit_code_addr = ecx_val;

    if (g_dump_method_info_detail) {
        //dprintf("method id = 0x%x, code address = 0x%08x\n", method_id, ecx_val);
    }

    for(auto id : g_method_ids_need_to_set_bp) {
        if (id == method_id) {
            std::string bp = "bu 0x";
            char bp_addr[9] = {0};
            sprintf_s(bp_addr, "%08x", ecx_val);
            bp += bp_addr;
            if (!ExtExecuteCmd(bp.c_str())) {
                return;
            }
            break;
        }
    }

}

/***********************************************************
 * !HandleHookName
 *
 * Purpose: WINDBG will call this API when the user types !HandleHookName
 *          
 *
 *  Parameters:
 *     !HandleHookName <method_name>
 *
 *  Return Values:
 *     N/A
 *
 ***********************************************************/
DECLARE_API (HandleHookName)
{
    ULONG_PTR method_name_ptr = GetExpression(args);
    std::string method_name = ExtGetStringFromAddr(method_name_ptr);

    if (g_dump_method_info_detail) {
        dprintf("Call [%s]\n", method_name.c_str());
    }

    std::set<std::string>::iterator iter = g_method_name_need_to_set_bp.begin();
    for(; iter != g_method_name_need_to_set_bp.end(); ++iter) {
        std::string name = *iter;
        if (-1 != method_name.find(name) && -1 != name.find(method_name)) {
            std::string bp;
			char* cmd = "bu 0x%08x \"";
			char* cmd2 = ".echo  BreakPoint at [%s];";
            char bp_addr[128] = {0};
            sprintf_s(bp_addr, cmd, g_last_jit_code_addr);
            bp += bp_addr;
			memset(bp_addr, 0, 128);
			sprintf_s(bp_addr, cmd2, method_name.c_str());
			bp += bp_addr;
			if (g_dump_method_info_detail_ex) {
				bp += "gc";
			}
			bp += "\" ";
			//dprintf("bp is %s\n", bp.c_str());
            if (!ExtExecuteCmd(bp.c_str())) {
                return;
            }
            break;
        }
    }

}

/***********************************************************
 * !EnableDumpMethodInfo
 *
 * Purpose: WINDBG will call this API when the user types !EnableDumpMethodInfo
 *          
 *
 *  Parameters:
 *     !EnableDumpMethodInfo <value>
 *
 *  Return Values:
 *     N/A
 *
 ***********************************************************/
DECLARE_API (EnableTraceJit)
{
    if (!HookJit()){
        return;
    }
    ULONG_PTR flag = GetExpression(args);
    if (flag) {
		dprintf("Trace Jit method call is enable!\n");
        g_dump_method_info_detail = true;
    } else {
		dprintf("Trace Jit method call is disable!\n");
        g_dump_method_info_detail = false;
    }
    
}

/***********************************************************
 * !EnableDumpMethodInfo
 *
 * Purpose: WINDBG will call this API when the user types !EnableDumpMethodInfo
 *          
 *
 *  Parameters:
 *     !EnableDumpMethodInfo <value>
 *
 *  Return Values:
 *     N/A
 *
 ***********************************************************/
DECLARE_API (EnableTraceJitEx)
{
    if (!HookJit()){
        return;
    }
    ULONG_PTR flag = GetExpression(args);
    if (flag) {
		dprintf("Trace Jit method call is enable!\n");
        g_dump_method_info_detail_ex = true;
    } else {
		dprintf("Trace Jit method call is disable!\n");
        g_dump_method_info_detail_ex = false;
    }
    
}