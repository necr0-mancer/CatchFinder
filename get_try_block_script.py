import ida_ida
import ida_idaapi

import idautils
import ida_kernwin
import ida_segment
import ida_hexrays
import ida_lines
import ida_bytes
import ida_nalt
import ida_typeinf
import ida_xref
import ida_funcs
import ida_kernwin

# ======================= .PDATA EXCEPTION =======================
# ================================================================

UNN_FLAG_ERROR     = -0x01
UNW_FLAG_NHANDLER  = 0x00
UNW_FLAG_EHANDLER  = 0x01
UNW_FLAG_UHANDLER  = 0x02
UNW_FLAG_CHAININFO = 0x04

UWOP_PUSH_NONVOL     = 0 # slot = 0
UWOP_ALLOC_LARGE     = 1 # slot = 1 (OpInfo = 0) slot = 2 (OpInfo = 1)
UWOP_ALLOC_SMALL     = 2 # slot = 0
UWOP_SET_FPREG       = 3 # slot = 0
UWOP_SAVE_NONVOL     = 4 # slot = 1
UWOP_SAVE_NONVOL_FAR = 5 # slot = 2
UWOP_SAVE_XMM128     = 8 # slot = 1
UWOP_SAVE_XMM128_FAR = 9 # slot = 2
UWOP_PUSH_MACHFRA_ME = 10 # slot = 0

SEGMENT_PDATA = ('.pdata', int, int)

for ea in idautils.Segments():
    psegment_t = ida_segment.getseg(ea)
    name_seg   = ida_segment.get_segm_name(psegment_t, 0)
    if name_seg.find(SEGMENT_PDATA[0]) != -1:
        SEGMENT_PDATA = (name_seg, psegment_t.start_ea, psegment_t.end_ea)
        break

print('[+] SEGMENT {0} \' {1} \' {2} '.format(
                        SEGMENT_PDATA[0],
                        hex(SEGMENT_PDATA[1]),
                        hex(SEGMENT_PDATA[2])
                        ))

# print(f'[+] ExceptionHandler={hex(ExceptionHandler)} ExceptionData={hex(ExceptionData)}')

result = []

class UnwindInfoChooser(ida_kernwin.Choose):
    def __init__(self, title, items):
        ida_kernwin.Choose.__init__(
            self,
            title,
            [
                ["ExceptionHandler", 16],
                ["ExceptionData", 16],
                ["dispOfHandler(catch-block)", 16],
            ],
            flags=ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self.items = items
    def OnGetSize(self):
        return len(self.items)
    def OnGetLine(self, n):
        return self.items[n]
    def OnSelectLine(self, n):

        ea1, ea2, ea3 = self.items[n]

        res = ida_kernwin.ask_buttons(
            f"{ea1}", f"{ea2}", f"{ea3}", 0,
            "Select an address to navigate to"
        )

        if res == 0:
            ida_kernwin.jumpto(int(ea1,16))
        elif res == 1:
            ida_kernwin.jumpto(int(ea2,16))
        elif res == -1:
            ida_kernwin.jumpto(int(ea3,16))
    

    
def XREF(ea_):
    xref_array = []
    for ref in idautils.DataRefsTo(ea_):
        if SEGMENT_PDATA[1] <= ref <= SEGMENT_PDATA[2]:
            xref_array.append((SEGMENT_PDATA[0], ref))
    return xref_array

def XREF_CALL(ea_):
    xref_array = []
    for xref in idautils.XrefsTo(ea_, ida_xref.XREF_ALL):
        if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
            call_ea  = xref.frm
            call_fun = ida_funcs.get_func(xref.frm)
            if call_fun:
                xref_array.append((call_ea, call_fun.start_ea))
    return xref_array

# FH4 compressed integer:
#   xxx0 -> 1 byte, xx01 -> 2 bytes, x011 -> 3 bytes, 0111 -> 4 bytes, 1111 -> 5 bytes
def read_compressed_uint(ea):
    b0 = ida_bytes.get_byte(ea)
    if (b0 & 0x01) == 0:            # xxx0 -> 1 byte
        return (b0 >> 1), 1
    elif (b0 & 0x03) == 0x01:       # xx01 -> 2 bytes
        return ((b0 >> 2) | (ida_bytes.get_byte(ea + 1) << 6)), 2
    elif (b0 & 0x07) == 0x03:       # x011 -> 3 bytes
        return ((b0 >> 3) |
                (ida_bytes.get_byte(ea + 1) << 5) |
                (ida_bytes.get_byte(ea + 2) << 13)), 3
    elif (b0 & 0x0F) == 0x07:       # 0111 -> 4 bytes
        return ((b0 >> 4) |
                (ida_bytes.get_byte(ea + 1) << 4) |
                (ida_bytes.get_byte(ea + 2) << 12) |
                (ida_bytes.get_byte(ea + 3) << 20)), 4
    else:                           # 1111 -> 5 bytes, full 32-bit value in tail
        return ida_bytes.get_dword(ea + 1), 5

# ea_ is ExceptionData
def FuncInfo4_Parser(ea_, ExceptionHandler, ExceptionData):
    class FuncInfoHeader:           # bits: lowest bit = first field
        def __init__(self, ea_):
            header             = ida_bytes.get_byte(ea_)
            self.isCatch       = header & 1
            self.isSeparated   = header >> 1 & 1
            self.BBT           = header >> 2 & 1
            self.UnwindMap     = header >> 3 & 1
            self.TryBlockMap   = header >> 4 & 1
            self.EHs           = header >> 5 & 1
            self.NoExcept      = header >> 6 & 1
            self.reserved      = header >> 7 & 1

    header = FuncInfoHeader(ea_)
    ea_    += 1 # +FuncInfoHeader

    image_base = ida_nalt.get_imagebase()
    dispUnwindMap    = 0
    dispTryBlockMap  = 0
    dispIPtoStateMap = 0
    dispFrame        = 0

    if(header.BBT):
        # bbtFlags - compressed uint32
        bbtFlags, sz = read_compressed_uint(ea_)
        ea_ += sz
    if(header.UnwindMap):
        dispUnwindMap    = ida_bytes.get_dword(ea_)
        ea_ += 4 # int32_t (4 bytes)
    if(header.TryBlockMap):
        dispTryBlockMap  = ida_bytes.get_dword(ea_)
        ea_ += 4 # int32_t (4 bytes)
    # dispIPtoStateMap - always present
    dispIPtoStateMap = ida_bytes.get_dword(ea_)
    ea_ += 4 # int32_t (4 bytes)
    if(header.isCatch):
        # dispFrame - compressed uint32
        dispFrame, sz = read_compressed_uint(ea_)
        ea_ += sz

    # TryBlockMap -> HandlerMap
    if(header.TryBlockMap and dispTryBlockMap != 0):
        ea_TryBlockMap = image_base + dispTryBlockMap
        NumEntries, sz = read_compressed_uint(ea_TryBlockMap)
        ea_TryBlockMap += sz

        if NumEntries > 0x1000: # sanity
            print(f"[!] suspicious TryBlockMap NumEntries={hex(NumEntries)} at {hex(ea_TryBlockMap)}")
            return

        for _ in range(NumEntries):
            # tryLow/tryHigh/catchHigh - compressed (state + 1), dispHandlerArray - int32 RVA
            tryLow,    sz = read_compressed_uint(ea_TryBlockMap); ea_TryBlockMap += sz
            tryHigh,   sz = read_compressed_uint(ea_TryBlockMap); ea_TryBlockMap += sz
            catchHigh, sz = read_compressed_uint(ea_TryBlockMap); ea_TryBlockMap += sz
            dispHandlerArray = ida_bytes.get_dword(ea_TryBlockMap); ea_TryBlockMap += 4

            if dispHandlerArray == 0:
                continue

            ea_HandlerMap = image_base + dispHandlerArray
            NumEntries_HandlerMap, sz = read_compressed_uint(ea_HandlerMap)
            ea_HandlerMap += sz

            if NumEntries_HandlerMap > 0x1000: # sanity
                print(f"[!] suspicious HandlerMap NumEntries={hex(NumEntries_HandlerMap)} at {hex(ea_HandlerMap)}")
                continue

            for _h in range(NumEntries_HandlerMap):
                class HandlerTypeHeader: # bits: lowest bit = first field
                    def __init__(self, ea_):
                        header            = ida_bytes.get_byte(ea_)
                        self.adjectives   = header & 1
                        self.dispType     = header >> 1 & 1
                        self.dispCatchObj = header >> 2 & 1
                        self.contIsRVA    = header >> 3 & 1
                        self.contAddr     = header >> 4 & 3
                        self.unused       = header >> 6 & 3

                head_HandlerMap = HandlerTypeHeader(ea_HandlerMap)
                ea_HandlerMap += 1

                if(head_HandlerMap.adjectives):      # compressed
                    val, sz = read_compressed_uint(ea_HandlerMap); ea_HandlerMap += sz
                if(head_HandlerMap.dispType):        # int32
                    dispType = ida_bytes.get_dword(ea_HandlerMap); ea_HandlerMap += 4
                if(head_HandlerMap.dispCatchObj):    # compressed
                    val, sz = read_compressed_uint(ea_HandlerMap); ea_HandlerMap += sz
                # dispOfHandler - always present, int32 RVA
                dispOfHandler = ida_bytes.get_dword(ea_HandlerMap); ea_HandlerMap += 4
                # continuation addresses: count = contAddr
                for _c in range(head_HandlerMap.contAddr):
                    if head_HandlerMap.contIsRVA:    # 4-byte RVA
                        cont = ida_bytes.get_dword(ea_HandlerMap); ea_HandlerMap += 4
                    else:                            # compressed, function-relative
                        cont, sz = read_compressed_uint(ea_HandlerMap); ea_HandlerMap += sz

                catch_address = image_base + dispOfHandler
                print(f"[+] dispOfHandler: {hex(catch_address)}")
                result.append([hex(ExceptionHandler), hex(ExceptionData), hex(catch_address)])



def RUNTIME_FUNCTION(ea, xref_array):

    def UNWIND_ (ea_, unwind_info) -> bool:

        version        = ida_bytes.get_byte(unwind_info) &  0x7 # Version 
        flags          = ida_bytes.get_byte(unwind_info) >> 0x3 # Flags

        PrologSize     = ida_bytes.get_byte(unwind_info + 1)
        CntUnwindCodes = ida_bytes.get_byte(unwind_info + 2)
        # FrameRegister & FrameOffset
        FrameRegister  = ida_bytes.get_byte(unwind_info + 3)  &  0xF     
        FrameOffset    = ida_bytes.get_byte(unwind_info + 3)  >> 4

        print(f'Version={hex(version)} Flags={hex(flags)} PrologSize={hex(PrologSize)} CntUnwindCodes={hex(CntUnwindCodes)} FrameRegister={hex(FrameRegister)} FrameOffset={hex(FrameOffset)}')

        i  = 0
        ea = 0
        addidation_code = UWOP_PUSH_NONVOL

        PrologOff = 0
        UnwindOp  = 0
        OpInfo    = 0

        while i < CntUnwindCodes:

            trac_0   = addidation_code == UWOP_PUSH_NONVOL
            trac_0   = trac_0 or addidation_code == UWOP_ALLOC_SMALL
            trac_0   = trac_0 or addidation_code == UWOP_SET_FPREG
            trac_0   = trac_0 or addidation_code == UWOP_PUSH_MACHFRA_ME

            trac_1   = addidation_code == UWOP_SAVE_NONVOL
            trac_1   = trac_1 or addidation_code == UWOP_SAVE_XMM128

            trac_2   = addidation_code == UWOP_SAVE_NONVOL_FAR
            trac_2   = trac_2 or addidation_code == UWOP_SAVE_XMM128_FAR

            code_    = [0,0]
            if trac_0:
                ea = unwind_info + 4 + i * 2
                PrologOff  = ida_bytes.get_byte(ea)

                ea += 1
                b_0_4      = ida_bytes.get_byte(ea)
                UnwindOp   = b_0_4 & 0xF
                OpInfo     = b_0_4 >> 4

                addidation_code = UnwindOp
                i += 1

                if UnwindOp not in (UWOP_ALLOC_LARGE, UWOP_SAVE_NONVOL, UWOP_SAVE_XMM128, UWOP_SAVE_NONVOL_FAR, UWOP_SAVE_XMM128_FAR):
                    print(f'[{i}] PrologOff={hex(PrologOff)} UnwindOp={hex(UnwindOp)} OpInfo={hex(OpInfo)}')

            elif trac_1:
                ea = unwind_info + 4 + i * 2
                code_[0] = ida_bytes.get_word(ea)

                print(f'[{i}] PrologOff={hex(PrologOff)} UnwindOp={hex(UnwindOp)} OpInfo={hex(OpInfo)} & AddidationCode={hex(code_[0])}')
                addidation_code = UWOP_PUSH_NONVOL
                i += 1
                pass
            elif trac_2:
                ea = unwind_info + 4 + i * 2
                code_[0] = ida_bytes.get_word(ea)
                code_[1] = ida_bytes.get_word(ea + 2)

                print(f'[{i}] PrologOff={hex(PrologOff)} UnwindOp={hex(UnwindOp)} OpInfo={hex(OpInfo)} & AddidationCode(0)={hex(code_[0])} AddidationCode(1)={hex(code_[1])}')
                addidation_code = UWOP_PUSH_NONVOL
                i += 2
                pass
            elif addidation_code == UWOP_ALLOC_LARGE:
                ea = unwind_info + 4 + i * 2
                if OpInfo  == 0:
                    code_[0] = ida_bytes.get_word(ea)
                    print(f'[{i}] PrologOff={hex(PrologOff)} UnwindOp={hex(UnwindOp)} OpInfo={hex(OpInfo)} & AddidationCode={hex(code_[0])}')
                    i += 1
                elif OpInfo == 1:
                    code_[0] = ida_bytes.get_word(ea)
                    code_[1] = ida_bytes.get_word(ea + 2)
                    print(f'[{i}] PrologOff={hex(PrologOff)} UnwindOp={hex(UnwindOp)} OpInfo={hex(OpInfo)} & AddidationCode={hex(code_[0])}')
                    i += 2
                
                addidation_code = UWOP_PUSH_NONVOL

        # ================ handler area (aligned to 4) ================
        image_base       = ida_nalt.get_imagebase()
        handler_offset = (4 + 2 * CntUnwindCodes + 3) & ~3
        handler_ea     = unwind_info + handler_offset

        if flags == UNW_FLAG_NHANDLER:
            print(f'[!] Flags={hex(flags)}:UNW_FLAG_NHANDLER(0) __try/__except, __try/__finally None')
            return UNW_FLAG_NHANDLER

        if flags & UNW_FLAG_CHAININFO:
            # chained RUNTIME_FUNCTION: BeginAddress, EndAddress, UnwindData
            chained_unwind = image_base + ida_bytes.get_dword(handler_ea + 8)
            return UNWIND_(ea, unwind_info=chained_unwind)

        if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
            # ====================== Payload ==================================
            ExceptionHandler = image_base + ida_bytes.get_dword(handler_ea)
            ExceptionData    = image_base + ida_bytes.get_dword(handler_ea + 4)
            # =================================================================
            # ea_, ExceptionHandler, ExceptionData

            print(f'[+] ExceptionHandler={hex(ExceptionHandler)} ExceptionData={hex(ExceptionData)}')
            FuncInfo4_Parser(ExceptionData, ExceptionHandler, ExceptionData)

            #result.append([hex(ea_), hex(ExceptionHandler), hex(ExceptionData)])

            return (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)
        
        return UNN_FLAG_ERROR

    for ref in xref_array:
        
        function_start = 0 # .pdata:???+0
        function_end   = 0 # .pdata:???+4
        unwind_info    = 0 # .pdata:???+8

        image_base     = ida_nalt.get_imagebase()
        function_start = image_base + ida_bytes.get_dword(ref[1])
        function_end   = image_base + ida_bytes.get_dword(ref[1] + 4)
        unwind_info    = image_base + ida_bytes.get_dword(ref[1] + 8)

        print('{0} {1} {2}'.format(
            hex(function_start),
            hex(function_end),
            hex(unwind_info)
        ))

        if UNWIND_(ea, unwind_info=unwind_info) == UNW_FLAG_NHANDLER:
            for call_fun in XREF_CALL(ea):
                xref_array_fun = XREF(call_fun[1]) # addres_fun
                RUNTIME_FUNCTION(call_fun[1], xref_array_fun) # addres_fun, list(.pdata(list(call_fun)))
        #print('[+] Xref {0} \' {1} \' {2}'.format(ref[0], hex(ref[1]), ida_lines.generate_disasm_line(ref[1], flags=1)))
            
ea = ida_kernwin.get_screen_ea()
xref_array = XREF(ea)
RUNTIME_FUNCTION(ea, xref_array)

choser = UnwindInfoChooser(".PDATA EXCEPTION", result)
choser.Show()


