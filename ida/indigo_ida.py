import idaapi
import idautils
import idc


def get_third_arg(call_ea):
    # get the function frame
    func = idaapi.get_func(call_ea)
    if not func:
        return None

    args = []
    ea = call_ea

    while ea != idaapi.BADADDR and len(args) < 3:
        # create an instruction decoder and get args on stack
        dis = idautils.DecodeInstruction(ea)
        if dis and dis.get_canon_mnem() == 'push':
            args.append(idc.get_operand_value(ea, 0))
        ea = idc.prev_head(ea)

    if len(args) >= 2:
        return args[1]

    return None


def get_string_at_addr(addr):
    return idc.get_strlit_contents(addr)


def main():
    func_name = "QdtString_ctor"
    log_func_ea = idc.get_name_ea_simple(func_name)

    if log_func_ea == idaapi.BADADDR:
        print(f'function {func_name} not found')
        return

    third_args = []
    for ref in idautils.CodeRefsTo(log_func_ea, 1):
        third_arg = get_third_arg(ref)
        if third_arg is not None:
            third_arg_str = get_string_at_addr(third_arg)
            if third_arg_str:
                third_args.append(third_arg_str.decode('utf-8'))

    third_args.sort(key=lambda path: path)

    out_file = "C:\\Users\\marti\\sources.txt"
    with open(out_file, "w") as f:
        for arg in third_args:
            f.write(f'{arg}\n')

    print(f'sorted and written to {out_file}')


if __name__ == '__main__':
    main()
