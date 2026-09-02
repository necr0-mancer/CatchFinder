

import ida_idaapi
import ida_kernwin
import ida_segment
import ida_bytes
import ida_nalt
import ida_xref
import ida_funcs
import ida_ida
import idautils

# =====================================================================
# Constants
# =====================================================================
UNN_FLAG_ERROR     = -0x01
UNW_FLAG_NHANDLER  = 0x00
UNW_FLAG_EHANDLER  = 0x01
UNW_FLAG_UHANDLER  = 0x02
UNW_FLAG_CHAININFO = 0x04

UWOP_PUSH_NONVOL     = 0
UWOP_ALLOC_LARGE     = 1
UWOP_ALLOC_SMALL     = 2
UWOP_SET_FPREG       = 3
UWOP_SAVE_NONVOL     = 4
UWOP_SAVE_NONVOL_FAR = 5
UWOP_SAVE_XMM128     = 8
UWOP_SAVE_XMM128_FAR = 9
UWOP_PUSH_MACHFRA_ME = 10

# colors (BGR)
COLOR_HANDLER = 0x5656FF   # orange-ish  -> ExceptionHandler column
COLOR_DATA    = 0x9999FF   # light orange -> ExceptionData column
COLOR_CATCH   = 0xB088FF   # purple      -> dispOfHandler (catch) column

SEGMENT_PDATA = ('.pdata', 0, 0)
result = []

# =====================================================================
# Helpers
# =====================================================================
def locate_pdata_segment():
    global SEGMENT_PDATA
    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        name = ida_segment.get_segm_name(seg, 0)
        if '.pdata' in name:
            SEGMENT_PDATA = (name, seg.start_ea, seg.end_ea)
            break
    print('[+] SEGMENT %s %s %s' % (SEGMENT_PDATA[0],
                                     hex(SEGMENT_PDATA[1]),
                                     hex(SEGMENT_PDATA[2])))

# FH4 compressed integer:
#   xxx0 -> 1 byte, xx01 -> 2, x011 -> 3, 0111 -> 4, 1111 -> 5
def read_compressed_uint(ea):
    b0 = ida_bytes.get_byte(ea)
    if (b0 & 0x01) == 0:
        return (b0 >> 1), 1
    elif (b0 & 0x03) == 0x01:
        return ((b0 >> 2) | (ida_bytes.get_byte(ea + 1) << 6)), 2
    elif (b0 & 0x07) == 0x03:
        return ((b0 >> 3) | (ida_bytes.get_byte(ea + 1) << 5) |
                (ida_bytes.get_byte(ea + 2) << 13)), 3
    elif (b0 & 0x0F) == 0x07:
        return ((b0 >> 4) | (ida_bytes.get_byte(ea + 1) << 4) |
                (ida_bytes.get_byte(ea + 2) << 12) |
                (ida_bytes.get_byte(ea + 3) << 20)), 4
    else:
        return ida_bytes.get_dword(ea + 1), 5


def XREF(ea_):
    out = []
    for ref in idautils.DataRefsTo(ea_):
        if SEGMENT_PDATA[1] <= ref <= SEGMENT_PDATA[2]:
            out.append((SEGMENT_PDATA[0], ref))
    return out


def XREF_CALL(ea_):
    out = []
    for xref in idautils.XrefsTo(ea_, ida_xref.XREF_ALL):
        if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
            fn = ida_funcs.get_func(xref.frm)
            if fn:
                out.append((xref.frm, fn.start_ea))
    return out

# =====================================================================
# FuncInfo4 parser
# =====================================================================
def FuncInfo4_Parser(ea_, ExceptionHandler, ExceptionData):
    class FuncInfoHeader:           # lowest bit = first field
        def __init__(self, ea_):
            h                  = ida_bytes.get_byte(ea_)
            self.isCatch       = h & 1
            self.isSeparated   = h >> 1 & 1
            self.BBT           = h >> 2 & 1
            self.UnwindMap     = h >> 3 & 1
            self.TryBlockMap   = h >> 4 & 1
            self.EHs           = h >> 5 & 1
            self.NoExcept      = h >> 6 & 1
            self.reserved      = h >> 7 & 1

    header = FuncInfoHeader(ea_)
    ea_   += 1

    image_base       = ida_nalt.get_imagebase()
    dispUnwindMap    = 0
    dispTryBlockMap  = 0
    dispIPtoStateMap = 0

    if header.BBT:
        v, sz = read_compressed_uint(ea_); ea_ += sz
    if header.UnwindMap:
        dispUnwindMap    = ida_bytes.get_dword(ea_); ea_ += 4
    if header.TryBlockMap:
        dispTryBlockMap  = ida_bytes.get_dword(ea_); ea_ += 4
    dispIPtoStateMap = ida_bytes.get_dword(ea_); ea_ += 4
    if header.isCatch:
        v, sz = read_compressed_uint(ea_); ea_ += sz

    if not (header.TryBlockMap and dispTryBlockMap):
        return

    ea_TryBlockMap = image_base + dispTryBlockMap
    NumEntries, sz = read_compressed_uint(ea_TryBlockMap)
    ea_TryBlockMap += sz

    if NumEntries > 0x1000:
        print(f"[!] suspicious TryBlockMap NumEntries={hex(NumEntries)} at {hex(ea_TryBlockMap)}")
        return

    for _ in range(NumEntries):
        tl, sz = read_compressed_uint(ea_TryBlockMap); ea_TryBlockMap += sz
        th, sz = read_compressed_uint(ea_TryBlockMap); ea_TryBlockMap += sz
        ch, sz = read_compressed_uint(ea_TryBlockMap); ea_TryBlockMap += sz
        dispHandlerArray = ida_bytes.get_dword(ea_TryBlockMap); ea_TryBlockMap += 4

        if dispHandlerArray == 0:
            continue

        ea_HandlerMap = image_base + dispHandlerArray
        NumH, sz = read_compressed_uint(ea_HandlerMap)
        ea_HandlerMap += sz

        if NumH > 0x1000:
            print(f"[!] suspicious HandlerMap NumEntries={hex(NumH)} at {hex(ea_HandlerMap)}")
            continue

        for _h in range(NumH):
            class HandlerTypeHeader:
                def __init__(self, ea_):
                    h                 = ida_bytes.get_byte(ea_)
                    self.adjectives   = h & 1
                    self.dispType     = h >> 1 & 1
                    self.dispCatchObj = h >> 2 & 1
                    self.contIsRVA    = h >> 3 & 1
                    self.contAddr     = h >> 4 & 3
                    self.unused       = h >> 6 & 3

            head = HandlerTypeHeader(ea_HandlerMap)
            ea_HandlerMap += 1

            if head.adjectives:
                v, sz = read_compressed_uint(ea_HandlerMap); ea_HandlerMap += sz
            if head.dispType:
                dt = ida_bytes.get_dword(ea_HandlerMap); ea_HandlerMap += 4
            if head.dispCatchObj:
                v, sz = read_compressed_uint(ea_HandlerMap); ea_HandlerMap += sz
            dispOfHandler = ida_bytes.get_dword(ea_HandlerMap); ea_HandlerMap += 4

            for _c in range(head.contAddr):
                if head.contIsRVA:
                    c = ida_bytes.get_dword(ea_HandlerMap); ea_HandlerMap += 4
                else:
                    c, sz = read_compressed_uint(ea_HandlerMap); ea_HandlerMap += sz

            catch_addr = image_base + dispOfHandler
            print(f"[+] dispOfHandler: {hex(catch_addr)}")
            result.append([hex(ExceptionHandler), hex(ExceptionData), hex(catch_addr)])

# =====================================================================
# RUNTIME_FUNCTION / UNWIND_INFO
# =====================================================================
def RUNTIME_FUNCTION(ea, xref_array):
    def UNWIND_(ea_, unwind_info):
        version        = ida_bytes.get_byte(unwind_info) & 0x7
        flags          = ida_bytes.get_byte(unwind_info) >> 0x3
        PrologSize     = ida_bytes.get_byte(unwind_info + 1)
        CntUnwindCodes = ida_bytes.get_byte(unwind_info + 2)
        FrameRegister  = ida_bytes.get_byte(unwind_info + 3) & 0xF
        FrameOffset    = ida_bytes.get_byte(unwind_info + 3) >> 4

        print(f'Version={hex(version)} Flags={hex(flags)} PrologSize={hex(PrologSize)} '
              f'CntUnwindCodes={hex(CntUnwindCodes)} FrameRegister={hex(FrameRegister)} FrameOffset={hex(FrameOffset)}')

        i = 0
        addidation_code = UWOP_PUSH_NONVOL
        PrologOff = UnwindOp = OpInfo = 0

        while i < CntUnwindCodes:
            trac_0 = addidation_code in (UWOP_PUSH_NONVOL, UWOP_ALLOC_SMALL,
                                          UWOP_SET_FPREG, UWOP_PUSH_MACHFRA_ME)
            trac_1 = addidation_code in (UWOP_SAVE_NONVOL, UWOP_SAVE_XMM128)
            trac_2 = addidation_code in (UWOP_SAVE_NONVOL_FAR, UWOP_SAVE_XMM128_FAR)

            code_ = [0, 0]
            if trac_0:
                ea_u = unwind_info + 4 + i * 2
                PrologOff = ida_bytes.get_byte(ea_u)
                b = ida_bytes.get_byte(ea_u + 1)
                UnwindOp = b & 0xF
                OpInfo   = b >> 4
                addidation_code = UnwindOp
                i += 1
                if UnwindOp not in (UWOP_ALLOC_LARGE, UWOP_SAVE_NONVOL, UWOP_SAVE_XMM128,
                                    UWOP_SAVE_NONVOL_FAR, UWOP_SAVE_XMM128_FAR):
                    print(f'[{i}] PrologOff={hex(PrologOff)} UnwindOp={hex(UnwindOp)} OpInfo={hex(OpInfo)}')
            elif trac_1:
                eu = unwind_info + 4 + i * 2
                code_[0] = ida_bytes.get_word(eu)
                print(f'[{i}] PrologOff={hex(PrologOff)} UnwindOp={hex(UnwindOp)} OpInfo={hex(OpInfo)} '
                      f'AddidationCode={hex(code_[0])}')
                addidation_code = UWOP_PUSH_NONVOL
                i += 1
            elif trac_2:
                eu = unwind_info + 4 + i * 2
                code_[0] = ida_bytes.get_word(eu)
                code_[1] = ida_bytes.get_word(eu + 2)
                print(f'[{i}] PrologOff={hex(PrologOff)} UnwindOp={hex(UnwindOp)} OpInfo={hex(OpInfo)} '
                      f'AddidationCode(0)={hex(code_[0])} AddidationCode(1)={hex(code_[1])}')
                addidation_code = UWOP_PUSH_NONVOL
                i += 2
            elif addidation_code == UWOP_ALLOC_LARGE:
                eu = unwind_info + 4 + i * 2
                if OpInfo == 0:
                    code_[0] = ida_bytes.get_word(eu)
                    print(f'[{i}] PrologOff={hex(PrologOff)} UnwindOp={hex(UnwindOp)} OpInfo={hex(OpInfo)} '
                          f'AddidationCode={hex(code_[0])}')
                    i += 1
                else:
                    code_[0] = ida_bytes.get_word(eu)
                    code_[1] = ida_bytes.get_word(eu + 2)
                    print(f'[{i}] PrologOff={hex(PrologOff)} UnwindOp={hex(UnwindOp)} OpInfo={hex(OpInfo)} '
                          f'AddidationCode={hex(code_[0])}')
                    i += 2
                addidation_code = UWOP_PUSH_NONVOL

        image_base     = ida_nalt.get_imagebase()
        handler_offset = (4 + 2 * CntUnwindCodes + 3) & ~3
        handler_ea     = unwind_info + handler_offset

        if flags == UNW_FLAG_NHANDLER:
            print(f'[!] Flags={hex(flags)}:UNW_FLAG_NHANDLER no handlers')
            return UNW_FLAG_NHANDLER
        if flags & UNW_FLAG_CHAININFO:
            chained = image_base + ida_bytes.get_dword(handler_ea + 8)
            return UNWIND_(ea_, unwind_info=chained)
        if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
            ExceptionHandler = image_base + ida_bytes.get_dword(handler_ea)
            ExceptionData    = image_base + ida_bytes.get_dword(handler_ea + 4)
            print(f'[+] ExceptionHandler={hex(ExceptionHandler)} ExceptionData={hex(ExceptionData)}')
            FuncInfo4_Parser(ExceptionData, ExceptionHandler, ExceptionData)
            return (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)
        return UNN_FLAG_ERROR

    for ref in xref_array:
        image_base     = ida_nalt.get_imagebase()
        function_start = image_base + ida_bytes.get_dword(ref[1])
        function_end   = image_base + ida_bytes.get_dword(ref[1] + 4)
        unwind_info    = image_base + ida_bytes.get_dword(ref[1] + 8)

        print(f'{hex(function_start)} {hex(function_end)} {hex(unwind_info)}')

        if UNWIND_(ea, unwind_info=unwind_info) == UNW_FLAG_NHANDLER:
            for call_ea, fn_start in XREF_CALL(ea):
                RUNTIME_FUNCTION(fn_start, XREF(fn_start))

# =====================================================================
# Choose window
# =====================================================================
class UnwindInfoChooser(ida_kernwin.Choose):
    def __init__(self, title, items):
        ida_kernwin.Choose.__init__(
            self, title,
            [
                ["ExceptionHandler", 16],
                ["ExceptionData", 16],
                ["dispOfHandler(catch-block)", 16],
            ],
            flags=ida_kernwin.Choose.CH_CAN_REFRESH)
        self.items = items

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        ea1, ea2, ea3 = self.items[n]
        res = ida_kernwin.ask_buttons(
            ea1, ea2, ea3, 0, "Jump to:")
        if res == 0:
            ida_kernwin.jumpto(int(ea1, 16))
        elif res == 1:
            ida_kernwin.jumpto(int(ea2, 16))
        elif res == -1:
            ida_kernwin.jumpto(int(ea3, 16))

    def OnGetLineAttr(self, n):
        # DA0/TD0 format: line colors = "DA<len0><len1>...TD<color0><color1>..."
        ea1, ea2, ea3 = (int(x, 16) for x in self.items[n])
        da = "%DA" + "".join(chr(len(x)) for x in self.items[n])
        td = "%TD" + "".join((
            chr(COLOR_HANDLER & 0xFF), chr((COLOR_HANDLER >> 8) & 0xFF), chr((COLOR_HANDLER >> 16) & 0xFF),
            chr(COLOR_DATA & 0xFF), chr((COLOR_DATA >> 8) & 0xFF), chr((COLOR_DATA >> 16) & 0xFF),
            chr(COLOR_CATCH & 0xFF), chr((COLOR_CATCH >> 8) & 0xFF), chr((COLOR_CATCH >> 16) & 0xFF)
        ))
        return [ida_kernwin.CHCOL_PLAIN ,
                da + td]

# =====================================================================
# Entry / plugin wrapper
# =====================================================================
def find_catches():
    locate_pdata_segment()
    global result
    result = []
    ea = ida_kernwin.get_screen_ea()
    RUNTIME_FUNCTION(ea, XREF(ea))
    UnwindInfoChooser(".PDATA EXCEPTION", result).Show()


class CatchFinderAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        try:
            find_catches()
        except Exception as exc:
            ida_kernwin.warning(f"[CatchFinder] {exc}")
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class CatchFinderPlugin(ida_idaapi.plugin_t):
    flags         = ida_idaapi.PLUGIN_UNL
    comment       = "Locate C++ EH catch-handler addresses from FH4 metadata"
    help          = ("CatchFinder: .pdata RUNTIME_FUNCTION -> UNWIND_INFO -> "
                     "FuncInfo4 -> TryBlockMap4 -> HandlerMap4 -> dispOfHandler")
    wanted_name   = "CatchFinder"
    wanted_hotkey = "Ctrl-Shift-C"

    def init(self):
        if not ida_ida.inf_is_64bit():
            ida_kernwin.msg("[CatchFinder] 32-bit IDB detected; FH4 is relevant for amd64/x64\n")
            return ida_idaapi.PLUGIN_SKIP
        ad = ida_kernwin.action_desc_t(
            "catchfinder:run",
            "CatchFinder: find catch handlers",
            CatchFinderAction(),
            self.wanted_hotkey,
            "Parse FH4 and list catch handler addresses", -1)
        ida_kernwin.register_action(ad)
        ida_kernwin.attach_action_to_menu("Edit/Plugins/CatchFinder",
                                          "catchfinder:run", ida_kernwin.SETMENU_APP)
        ida_kernwin.msg("[CatchFinder] loaded (Ctrl-Shift-C)\n")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        try:
            find_catches()
        except Exception as exc:
            ida_kernwin.warning(f"[CatchFinder] {exc}")

    def term(self):
        ida_kernwin.unregister_action("catchfinder:run")
        ida_kernwin.msg("[CatchFinder] unloaded\n")


def PLUGIN_ENTRY():
    return CatchFinderPlugin()
