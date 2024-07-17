import idc
import idautils


def find_rtti_type_descriptors():
    for seg_ea in idautils.Segments():
        for head in idautils.Heads(seg_ea, idc.get_segm_end(seg_ea)):
            name = idc.get_name(head)
            if name and (name.startswith("_ZTI") or name.startswith("??_R")):
                print("Found type descriptor: {} at 0x{:X}".format(name, head))
                find_vtables_from_rtti(head)


def find_vtables_from_rtti(type_desc_ea):
    for xref in idautils.XrefsTo(type_desc_ea):
        if idc.is_data(idc.get_full_flags(xref.frm)):
            print("Potential vtable reference at 0x{:X}".format(xref.frm))
            inspect_vtable(xref.frm)


def inspect_vtable(vtable_ea):
    print("Inspecting vtable at 0x{:X}".format(vtable_ea))
    for i in range(20):  # Inspect the first 20 entries
        ea = vtable_ea + i * idc.get_item_size(vtable_ea)
        func_addr = idc.get_wide_dword(ea) if idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT == 0 else idc.get_qword(
            ea)
        if idc.is_code(idc.get_full_flags(func_addr)):
            func_name = idc.get_name(func_addr)
            print("  Entry {}: 0x{:X} -> {}".format(i, func_addr, func_name))
        else:
            break


find_rtti_type_descriptors()
