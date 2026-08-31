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
                ["EA", 16],
                ["ExceptionHandler", 16],
                ["ExceptionData", 16],
            ],
            flags=ida_kernwin.Choose.CH_CAN_REFRESH,
        )
        self.items = items
    def OnGetSize(self):
        return len(self.items)
    def OnGetLine(self, n):
        return self.items[n]
    def OnSelectLine(self, n):
        ea = int(self.items[n][0],16)
        ida_kernwin.jumpto(ea)
    

    
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

        # ================ ALIGN 4 =========================
        ea += 1
        if CntUnwindCodes % 2 != 0:
            ea += 2 # align 2 
        # ==================================================
        

        if flags == UNW_FLAG_NHANDLER:
            print(f'[!] Flags={hex(flags)}:UNW_FLAG_NHANDLER(0) __try/__except, __try/__finally None')
            return UNW_FLAG_NHANDLER

        if flags & UNW_FLAG_CHAININFO:
            return UNWIND_(ea)

        if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
            # ====================== Payload ================================== 
            image_base       = ida_nalt.get_imagebase()
            ExceptionHandler = image_base + ida_bytes.get_dword(ea)
            ExceptionData    = image_base + ida_bytes.get_dword(ea + 4)
            # ================================================================= 
            # ea_, ExceptionHandler, ExceptionData

            print(f'[+] ExceptionHandler={hex(ExceptionHandler)} ExceptionData={hex(ExceptionData)}')
            result.append([hex(ea_), hex(ExceptionHandler), hex(ExceptionData)])

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


