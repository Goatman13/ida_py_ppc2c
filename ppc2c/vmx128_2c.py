#VMX128 to C

from ida_bytes import *
from idaapi import *
from idc import *
import idaapi
import ida_bytes
import idc
import ppc2c.altivec2c

#VMX128
def vmaddfp128(vD, vA, vB):

	return "v{:d}[4xfloat] = (v{:d} * v{:d}) + v{:d}".format(vD, vA, vB, vD)

def vmaddcfp128(vD, vA, vB):

	return "v{:d}[4xfloat] = (v{:d} * v{:d}) + v{:d}".format(vD, vA, vD, vB)


def vmsum3fp128(vD, vA, vB):

	return "v{:d}[4xfloat] = (v{:d}[0] * v{:d}[0]) + (v{:d}[1] * v{:d}[1]) + (v{:d}[2] * v{:d}[2])".format(vD, vA, vB, vA, vB, vA, vB)

def vmsum4fp128(vD, vA, vB):

	return "v{:d}[4xfloat] = (v{:d}[0] * v{:d}[0]) + (v{:d}[1] * v{:d}[1]) + (v{:d}[2] * v{:d}[2]) + (v{:d}[3] * v{:d}[3])".format(vD, vA, vB, vA, vB, vA, vB, vA, vB)

def vnmsubfp128(vD, vA, vB):

	return "v{:d}[4xfloat] = (v{:d} * v{:d}) - v{:d}".format(vD, vA, vD, vB)

def vpermwi128(vD, vB, vPerm):

	z  = 0xAAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD
	sa = ((vPerm >> 6) & 3) * 32
	sb = ((vPerm >> 4) & 3) * 32
	sc = ((vPerm >> 2) & 3) * 32
	sd = ((vPerm >> 0) & 3) * 32
	a  = (z >> (96-sa)) & 0xFFFFFFFF
	b  = (z >> (96-sb)) & 0xFFFFFFFF
	c  = (z >> (96-sc)) & 0xFFFFFFFF
	d  = (z >> (96-sd)) & 0xFFFFFFFF
	return "v{:d}[128b] = v{:d}: {:08X}:{:08X}:{:08X}:{:08X}".format(vD,vB,a,b,c,d)

#def vpkd3d128(vD, Imm, vB, Shift): # Shift is vmxRc
#
#
#  mode = Imm >> 2;
#  pack = Imm & 0x3;
#  Value* v = f.LoadVR(vb);
#  switch (mode) {
#    case 0:  # VPACK_D3DCOLOR
#      v = f.Pack(v, PACK_TYPE_D3DCOLOR);
#      break;
#    case 1:  # VPACK_NORMSHORT2
#      v = f.Pack(v, PACK_TYPE_SHORT_2);
#      break;
#    case 2:  # VPACK_NORMPACKED32 2_10_10_10 w_z_y_x
#      v = f.Pack(v, PACK_TYPE_UINT_2101010);
#      break;
#    case 3:  # VPACK_FLOAT16_2 DXGI_FORMAT_R16G16_FLOAT
#      v = f.Pack(v, PACK_TYPE_FLOAT16_2);
#      break;
#    case 4:  # VPACK_NORMSHORT4
#      v = f.Pack(v, PACK_TYPE_SHORT_4);
#      break;
#    case 5:  # VPACK_FLOAT16_4 DXGI_FORMAT_R16G16B16A16_FLOAT
#      v = f.Pack(v, PACK_TYPE_FLOAT16_4);
#      break;
#    case 6:  # VPACK_NORMPACKED64 4_20_20_20 w_z_y_x
#      v = f.Pack(v, PACK_TYPE_ULONG_4202020);
#      break;
#    default:
#      return 0;
#  }
#
#
#  switch (pack) {
#    case 1:  // VPACK_32
#             // VPACK_32 & Shift = 3 puts lower 32 bits in x (leftmost slot).
#      switch (Shift) {
#        case 0:
#          control = MakePermuteMask(0, 0, 0, 1, 0, 2, 1, 3);
#          break;
#        case 1:
#          control = MakePermuteMask(0, 0, 0, 1, 1, 3, 0, 3);
#          break;
#        case 2:
#          control = MakePermuteMask(0, 0, 1, 3, 0, 2, 0, 3);
#          break;
#        case 3:
#          control = MakePermuteMask(1, 3, 0, 1, 0, 2, 0, 3);
#          break;
#        default:
#          assert_unhandled_case(Shift);
#          return 1;
#      }
#      break;
#    case 2:  // 64bit
#      switch (Shift) {
#        case 0:
#          control = MakePermuteMask(0, 0, 0, 1, 1, 2, 1, 3);
#          break;
#        case 1:
#          control = MakePermuteMask(0, 0, 1, 2, 1, 3, 0, 3);
#          break;
#        case 2:
#          control = MakePermuteMask(1, 2, 1, 3, 0, 2, 0, 3);
#          break;
#        case 3:
#          control = MakePermuteMask(1, 3, 0, 1, 0, 2, 0, 3);
#          break;
#        default:
#          assert_unhandled_case(Shift);
#          return 1;
#      }
#      break;
#    case 3:  // 64bit
#      switch (Shift) {
#        case 0:
#          control = MakePermuteMask(0, 0, 0, 1, 1, 2, 1, 3);
#          break;
#        case 1:
#          control = MakePermuteMask(0, 0, 1, 2, 1, 3, 0, 3);
#          break;
#        case 2:
#          control = MakePermuteMask(1, 2, 1, 3, 0, 2, 0, 3);
#          break;
#        case 3:
#          control = MakePermuteMask(0, 0, 0, 1, 0, 2, 1, 2);
#          break;
#        default:
#          assert_unhandled_case(Shift);
#          return 1;
#      }
#      break;
#    default:
#      assert_unhandled_case(pack);
#      return 1;
#  }
#  v = f.Permute(f.LoadConstantUint32(control), f.LoadVR(vd), v, INT32_TYPE);
#  f.StoreVR(vd, v);
#  return 0;
#}

def vrlimi128(vD, Imm, vB ,Rot):

	# rotate
	z  = 0x0123
	z  = (z << (Rot * 4)) | (z << (16 - (Rot * 4)))
	za = (z >> 12) & 3
	zb = (z >>  8) & 3
	zc = (z >>  4) & 3
	zd = (z >>  0) & 3
	# mask
	a = (Imm >> 3) & 1
	b = (Imm >> 2) & 1
	c = (Imm >> 1) & 1
	d = (Imm >> 0) & 1
	# result
	result = ".\n"
	if a == 1:
		result += "v{:d}[0].word = v{:d}[{:d}].word\n".format(vD,vB,za)
	else:
		result += "v{:d}[0].word = v{:d}[0].word\n".format(vD,vD)
	if b == 1:
		result += "v{:d}[1].word = v{:d}[{:d}].word\n".format(vD,vB,zb)
	else:
		result += "v{:d}[1].word = v{:d}[1].word\n".format(vD,vD)
	if c == 1:
		result += "v{:d}[2].word = v{:d}[{:d}].word\n".format(vD,vB,zc)
	else:
		result += "v{:d}[2].word = v{:d}[2].word\n".format(vD,vD)
	if d == 1:
		result += "v{:d}[3].word = v{:d}[{:d}].word".format(vD,vB,zd)
	else:
		result += "v{:d}[3].word = v{:d}[3].word".format(vD,vD)
	return result

def vsel128(vD, vA, vB):

	return "[128b] if bit in v{:d} == 0 take bit from v{:d}, else take bit from v{:d}".format(vD, vA, vB)


def Vmx128Asm2C(addr):

	opcode = get_wide_dword(addr)
	opcode_name = print_insn_mnem(addr)
	
	vmxA    = (opcode >> 16) & 0x1F | opcode & 0x20 | (opcode >> 4) & 0x40
	vmxB    = (opcode >> 11) & 0x1F | (opcode << 5) & 0x60
	vmxC    = (opcode >> 6)  & 0x7
	vmxD    = (opcode >> 21) & 0x1F | (opcode << 3) & 0x60
	vmxImm  = (opcode >> 16) & 0x1F
	vmxSimm = (opcode >> 16) & 0x1F
	vmxPerm = (opcode >> 16) & 0x1F | (opcode >> 1) & 0xE0
	vmxRc   = (opcode >> 6)  & 0x1
	vmxRot  = (opcode >> 6)  & 0x3
	vmxShb  = (opcode >> 6)  & 0xF

	if   opcode_name == "vaddfp128":     return ppc2c.altivec2c.vaddfp(vmxD, vmxA, vmxB)
	elif opcode_name == "vand128":       return ppc2c.altivec2c.vand(vmxD, vmxA, vmxB)
	elif opcode_name == "vandc128":      return ppc2c.altivec2c.vandc(vmxD, vmxA, vmxB)
	elif opcode_name == "vcfpsxws128":   return ppc2c.altivec2c.vctsxs(vmxD, vmxSimm, vmxB)
	elif opcode_name == "vcfpuxws128":   return ppc2c.altivec2c.vctuxs(vmxD, vmxImm, vmxB)
	elif opcode_name == "vcmpbfp128":    return ppc2c.altivec2c.vcmpbfp(vmxD, vmxA, vmxB, vmxRc)
	elif opcode_name == "vcmpbfp128.":   return ppc2c.altivec2c.vcmpbfp(vmxD, vmxA, vmxB, vmxRc)
	elif opcode_name == "vcmpeqfp128":   return ppc2c.altivec2c.vcmpeqfp(vmxD, vmxA, vmxB, vmxRc)
	elif opcode_name == "vcmpeqfp128.":  return ppc2c.altivec2c.vcmpeqfp(vmxD, vmxA, vmxB, vmxRc)
	elif opcode_name == "vcmpequw128":   return ppc2c.altivec2c.vcmpequw(vmxD, vmxA, vmxB, vmxRc)
	elif opcode_name == "vcmpequw128.":  return ppc2c.altivec2c.vcmpequw(vmxD, vmxA, vmxB, vmxRc)
	elif opcode_name == "vcmpgefp128":   return ppc2c.altivec2c.vcmpgefp(vmxD, vmxA, vmxB, vmxRc)
	elif opcode_name == "vcmpgefp128.":  return ppc2c.altivec2c.vcmpgefp(vmxD, vmxA, vmxB, vmxRc)
	elif opcode_name == "vcmpgtfp128":   return ppc2c.altivec2c.vcmpgtfp(vmxD, vmxA, vmxB, vmxRc)
	elif opcode_name == "vcmpgtfp128.":  return ppc2c.altivec2c.vcmpgtfp(vmxD, vmxA, vmxB, vmxRc)
	elif opcode_name == "vcsxwfp128":    return ppc2c.altivec2c.vcfsx(vmxD, vmxSimm, vmxB)
	elif opcode_name == "vcuxwfp128":    return ppc2c.altivec2c.vcfux(vmxD, vmxImm, vmxB)
	elif opcode_name == "vexptefp128":   return ppc2c.altivec2c.vexptefp(vmxD, vmxB)
	elif opcode_name == "vlogefp128":    return ppc2c.altivec2c.vlogefp(vmxD, vmxB)
	elif opcode_name == "vmaddcfp128":   return vmaddcfp128(vmxD, vmxA, vmxB)
	elif opcode_name == "vmaddfp128":    return vmaddfp128(vmxD, vmxA, vmxB)
	elif opcode_name == "vmaxfp128":     return ppc2c.altivec2c.vmaxfp(vmxD, vmxA, vmxB)
	elif opcode_name == "vminfp128":     return ppc2c.altivec2c.vminfp(vmxD, vmxA, vmxB)
	elif opcode_name == "vmrghw128":     return ppc2c.altivec2c.vmrghw(vmxD, vmxA, vmxB)
	elif opcode_name == "vmrglw128":     return ppc2c.altivec2c.vmrglw(vmxD, vmxA, vmxB)
	elif opcode_name == "vmsum3fp128":   return vmsum3fp128(vmxD, vmxA, vmxB)
	elif opcode_name == "vmsum4fp128":   return vmsum4fp128(vmxD, vmxA, vmxB)
	elif opcode_name == "vmulfp128":     return ppc2c.altivec2c.vmulfp(vmxD, vmxA, vmxB)
	elif opcode_name == "vnmsubfp128":   return vnmsubfp128(vmxD, vmxA, vmxB)
	elif opcode_name == "vnor128":       return ppc2c.altivec2c.vnor(vmxD, vmxA, vmxB)
	elif opcode_name == "vnot128":       return ppc2c.altivec2c.vnot(vmxD, vmxA)
	elif opcode_name == "vor128":        return ppc2c.altivec2c.vor(vmxD, vmxA, vmxB)
	elif opcode_name == "vmr128":        return ppc2c.altivec2c.vmr(vmxD, vmxA)
	elif opcode_name == "vperm128":      return ppc2c.altivec2c.vperm(vmxD, vmxA, vmxB, vmxC)
	elif opcode_name == "vpermwi128":    return vpermwi128(vmxD, vmxB, vmxPerm)
	elif opcode_name == "vpkshss128":    return ppc2c.altivec2c.vpkshss(vmxD, vmxA, vmxB)
	elif opcode_name == "vpkshus128":    return ppc2c.altivec2c.vpkshus(vmxD, vmxA, vmxB)
	elif opcode_name == "vpkswss128":    return ppc2c.altivec2c.vpkswss(vmxD, vmxA, vmxB)
	elif opcode_name == "vpkswus128":    return ppc2c.altivec2c.vpkswus(vmxD, vmxA, vmxB)
	elif opcode_name == "vpkuhum128":    return ppc2c.altivec2c.vpkuhum(vmxD, vmxA, vmxB)
	elif opcode_name == "vpkuhus128":    return ppc2c.altivec2c.vpkuhus(vmxD, vmxA, vmxB)
	elif opcode_name == "vpkuwum128":    return ppc2c.altivec2c.vpkuwum(vmxD, vmxA, vmxB)
	elif opcode_name == "vpkuwus128":    return ppc2c.altivec2c.vpkuwus(vmxD, vmxA, vmxB)
	elif opcode_name == "vrefp128":      return ppc2c.altivec2c.vrefp(vmxD, vmxB)
	elif opcode_name == "vrfim128":      return ppc2c.altivec2c.vrfim(vmxD, vmxB)
	elif opcode_name == "vrfin128":      return ppc2c.altivec2c.vrfin(vmxD, vmxB)
	elif opcode_name == "vrfip128":      return ppc2c.altivec2c.vrfip(vmxD, vmxB)
	elif opcode_name == "vrfiz128":      return ppc2c.altivec2c.vrfiz(vmxD, vmxB)
	elif opcode_name == "vrlw128":       return ppc2c.altivec2c.vrlw(vmxD, vmxA, vmxB)
	elif opcode_name == "vrlimi128":     return vrlimi128(vmxD, vmxImm, vmxB ,vmxRot)
	elif opcode_name == "vrsqrtefp128":  return ppc2c.altivec2c.vrsqrtefp(vmxD, vmxB)
	elif opcode_name == "vsel128":       return vsel128(vmxD, vmxA, vmxB)
	elif opcode_name == "vsldoi128":     return ppc2c.altivec2c.vsldoi(vmxD, vmxA, vmxB, vmxShb)
	elif opcode_name == "vslo128":       return ppc2c.altivec2c.vslo(vmxD, vmxA, vmxB)
	elif opcode_name == "vslw128":       return ppc2c.altivec2c.vslw(vmxD, vmxA, vmxB)
	elif opcode_name == "vspltisw128":   return ppc2c.altivec2c.vspltisw(vmxD, vmxSimm)
	elif opcode_name == "vspltw128":     return ppc2c.altivec2c.vspltw(vmxD, vmxImm, vmxB)
	elif opcode_name == "vsraw128":      return ppc2c.altivec2c.vsraw(vmxD, vmxA, vmxB)
	elif opcode_name == "vsro128":       return ppc2c.altivec2c.vsro(vmxD, vmxA, vmxB)
	elif opcode_name == "vsrw128":       return ppc2c.altivec2c.vsrw(vmxD, vmxA, vmxB)	
	elif opcode_name == "vsubfp128":     return ppc2c.altivec2c.vsubfp(vmxD, vmxA, vmxB)	
	elif opcode_name == "vupkhsb128":    return ppc2c.altivec2c.vupkhsb(vmxD, vmxB)
	elif opcode_name == "vupklsb128":    return ppc2c.altivec2c.vupklsb(vmxD, vmxB)
	elif opcode_name == "vupkhsh128":    return ppc2c.altivec2c.vupkhsh(vmxD, vmxB)
	elif opcode_name == "vupklsh128":    return ppc2c.altivec2c.vupklsh(vmxD, vmxB)
	elif opcode_name == "vxor128":       return ppc2c.altivec2c.vxor(vmxD, vmxA, vmxB)	
	# todo vpkd3d128
    # todo vupkd3d128
	
	return 0
