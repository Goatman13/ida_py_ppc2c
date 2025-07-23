#VSX / VSX-2 to C

from ida_bytes import *
from idaapi import *
from idc import *
import idaapi
import ida_bytes
import idc
import ppc2c.altivec2c

def xsabsdp(vsxD, vsxB):

	return "vs{:d}[0].double = abs(vs{:d}[0].double)".format(vsxD, vsxB)

def xsadddp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = vs{:d}[0].double + vs{:d}[0].double".format(vsxD, vsxA, vsxB)

def xsaddsp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].float = vs{:d}[0].float + vs{:d}[0].float".format(vsxD, vsxA, vsxB)

def xscmpudp(vsxBf, vsxA, vsxB):

	return "cr{:d} = compare_unordered(vs{:d}[0].double, vs{:d}[0].double)".format(vsxBf, vsxA, vsxB)

def xscpsgndp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = (vs{:d}[0].double & 0x80000000:00000000) | (vs{:d}[0].double & 0x7FFFFFFF:FFFFFFFF)".format(vsxD, vsxA, vsxB)

def xscvdpsp(vsxD, vsxB):

	return "vs{:d}[0].float = dptofp(vs{:d}[0].double)".format(vsxD, vsxB)

# fixme
def xscvdpspn(vsxD, vsxB):

	return "vs{:d}[0].float = dptofp(vs{:d}[0].double)".format(vsxD, vsxB)

def xscvdpsxds(vsxD, vsxB):

	return ""

#ok
def xscvdpsxws(vsxD, vsxB):

	return "vs{:d}[1].word = dptosi32(vs{:d}[0].double)".format(vsxD, vsxB)

def xscvdpuxds(vsxD, vsxB):

	return "vs{:d}[0].doubleword = dptoui64(vs{:d}[0].double)".format(vsxD, vsxB)

def xscvdpuxws(vsxD, vsxB):

	return "vs{:d}[1].word = dptoui32(vs{:d}[0].double)".format(vsxD, vsxB)

def xscvspdp(vsxD, vsxB):

	return "vs{:d}[0].double = dptofp(vs{:d}[0].float)".format(vsxD, vsxB)

#fixme
def xscvspdpn(vsxD, vsxB):

	return "vs{:d}[0].double = dptofp(vs{:d}[0].float)".format(vsxD, vsxB)

def xscvsxddp(vsxD, vsxB):

	return "vs{:d}[0].double = i64todp(vs{:d}[0].doubleword)".format(vsxD, vsxB)

def xscvsxdsp(vsxD, vsxB):

	return "vs{:d}[0].double = fptodp(i64tofp(vs{:d}[0].doubleword))".format(vsxD, vsxB)

def xscvuxddp(vsxD, vsxB):

	return "vs{:d}[0].double = u64todp(vs{:d}[0].doubleword)".format(vsxD, vsxB)

def xscvuxdsp(vsxD, vsxB):

	return "vs{:d}[0].double = fptodp(u64tofp(vs{:d}[0].doubleword))".format(vsxD, vsxB)

# todo Manual state this is fp divide, like wtf for half of those ops...
# xsdivsp need work too
def xsdivdp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = vs{:d}[0].double / vs{:d}[0].double".format(vsxD, vsxA, vsxB)

def xsdivsp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = fptodp(dptofp(vs{:d}[0].double / vs{:d}[0].double))".format(vsxD, vsxA, vsxB)

def xsmaddadp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = (vs{:d}[0].double * vs{:d}[0].double) + vs{:d}[0].double".format(vsxD, vsxA, vsxB, vsxD)

def xsmaddmdp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = (vs{:d}[0].double * vs{:d}[0].double) + vs{:d}[0].double".format(vsxD, vsxA, vsxD, vsxB)

def xsmaddasp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = fptodp(dptofp((vs{:d}[0].double * vs{:d}[0].double) + vs{:d}[0].double))".format(vsxD, vsxA, vsxB, vsxD)

def xsmaddmsp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = fptodp(dptofp((vs{:d}[0].double * vs{:d}[0].double) + vs{:d}[0].double))".format(vsxD, vsxA, vsxD, vsxB)

def xsmaxdp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = std::max(vs{:d}[0].double, vs{:d}[0].double)".format(vsxD, vsxA, vsxB)

def xsmindp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = std::min(vs{:d}[0].double, vs{:d}[0].double)".format(vsxD, vsxA, vsxB)

def xsmsubadp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = (vs{:d}[0].double * vs{:d}[0].double) - vs{:d}[0].double".format(vsxD, vsxA, vsxB, vsxD)

def xsmsubmdp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = (vs{:d}[0].double * vs{:d}[0].double) - vs{:d}[0].double".format(vsxD, vsxA, vsxD, vsxB)

def xsmsubasp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = fptodp(dptofp((vs{:d}[0].double * vs{:d}[0].double) - vs{:d}[0].double))".format(vsxD, vsxA, vsxB, vsxD)

def xsmsubmsp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = fptodp(dptofp((vs{:d}[0].double * vs{:d}[0].double) - vs{:d}[0].double))".format(vsxD, vsxA, vsxD, vsxB)

def xsmuldp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = vs{:d}[0].double * vs{:d}[0].double".format(vsxD, vsxA, vsxB)

def xsmulsp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = fptodp(dptofp(vs{:d}[0].double * vs{:d}[0].double))".format(vsxD, vsxA, vsxB)

def xsnabsdp(vsxD, vsxB):

	return "vs{:d}[0].double = vs{:d}[0].double | 0x80000000:00000000".format(vsxD, vsxB)

def xsnegdp(vsxD, vsxB):

	return "vs{:d}[0].double = vs{:d}[0].double | ~(vs{:d}[0].double & 0x80000000:00000000 )".format(vsxD, vsxB)

def xsnmaddadp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = ~((vs{:d}[0].double * vs{:d}[0].double) + vs{:d}[0].double)".format(vsxD, vsxA, vsxB, vsxD)

def xsnmaddmdp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = ~((vs{:d}[0].double * vs{:d}[0].double) + vs{:d}[0].double)".format(vsxD, vsxA, vsxD, vsxB)

def xsnmaddasp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = ~(fptodp(dptofp((vs{:d}[0].double * vs{:d}[0].double) + vs{:d}[0].double)))".format(vsxD, vsxA, vsxB, vsxD)

def xsnmaddmsp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = ~(fptodp(dptofp((vs{:d}[0].double * vs{:d}[0].double) + vs{:d}[0].double)))".format(vsxD, vsxA, vsxD, vsxB)

def xsnmsubadp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = ~((vs{:d}[0].double * vs{:d}[0].double) - vs{:d}[0].double)".format(vsxD, vsxA, vsxB, vsxD)

def xsnmsubmdp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = ~((vs{:d}[0].double * vs{:d}[0].double) - vs{:d}[0].double)".format(vsxD, vsxA, vsxD, vsxB)

def xsnmsubasp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = ~(fptodp(dptofp((vs{:d}[0].double * vs{:d}[0].double) - vs{:d}[0].double)))".format(vsxD, vsxA, vsxB, vsxD)

def xsnmsubmsp(vsxD, vsxA, vsxB):

	return "vs{:d}[0].double = ~(fptodp(dptofp((vs{:d}[0].double * vs{:d}[0].double) - vs{:d}[0].double)))".format(vsxD, vsxA, vsxD, vsxB)

#todo xsrdpi, xsrdpic, xsrdpim, xsrdpip, xsrdpiz

def xsredp(vsxD, vsxB):

	return "vs{:d}[0].double = 1 / vs{:d}[0].double".format(vsxD, vsxB)

def AltivecAsm2C(addr):

	opcode = get_wide_dword(addr)
	opcode_name = print_insn_mnem(addr)
	
	#VSX / VSX-2
	vsxA    = (opcode >> 16) & 0x1F | (opcode << 3) & 0x20
	vsxB    = (opcode >> 11) & 0x1F | (opcode << 4) & 0x20
	vsxC    = (opcode >> 6)  & 0x1F | (opcode << 2) & 0x20
	vsxD    = (opcode >> 21) & 0x1F | (opcode << 5) & 0x20
	vsxImm  = (opcode >> 16) & 0x3
	vsxBf   = (opcode >> 23) & 0x7
	vsxRc   = (opcode >> 10) & 0x1
	vsxDm  =  (opcode >> 7)  & 0x3
	vsxShw  = (opcode >> 7)  & 0x3

	if   opcode_name == "xsabsdp":       return xsabsdp(vsxD, vsxB)
	elif opcode_name == "xsabsdp":       return xsabsdp(vsxD, vsxB)

	return 0
