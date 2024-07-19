import idaapi
import idautils
import idc


def main():
    func_name = "sub_405260"
    func_ea = idc.get_name_ea_simple(func_name)
    if func_ea == idaapi.BADADDR:
        print(f'function {func_name} not found')
        return

    result = {}
    for x in [x for x in idautils.FuncItems(func_ea) if idaapi.is_call_insn(x)]:
        for xref in idautils.XrefsFrom(x, idaapi.XREF_FAR):
            if not xref.iscode:
                continue
            t = idc.get_func_name(xref.to)
            if not t:
                t = hex(xref.to)

            result[t] = True

    print(result)


if __name__ == '__main__':
    main()
