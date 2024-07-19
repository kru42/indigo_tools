import idaapi
import idautils
import idc


def main():
    func_name = 'sub_500C00'
    func_ea = idc.get_name_ea_simple(func_name)

    if func_ea == idaapi.BADADDR:
        print(f'function {func_name} not found')
        return

    out_file = 'xref_strings.txt'
    strings = list(idautils.Strings())

    with open(out_file, 'w') as f:
        i = 0
        for ref in idautils.CodeRefsTo(func_ea, 1):
            i += 1
            print(i)
            ref_func_name = idc.get_func_name(ref)
            if ref_func_name:
                func_start = idc.get_func_attr(ref, idc.FUNCATTR_START)
                func_end = idc.get_func_attr(ref, idc.FUNCATTR_END)

                for string in strings:
                    s = idc.get_strlit_contents(string.ea)
                    if s:
                        refs = idautils.XrefsTo(string.ea)
                        for ref2 in refs:
                            if func_start <= ref2.frm < func_end:
                                f.write(f'Function: {ref_func_name}\tValue: {string}')


if __name__ == '__main__':
    main()
