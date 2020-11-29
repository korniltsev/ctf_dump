import angr
import claripy
import IPython
from angr.sim_options import ZERO_FILL_UNCONSTRAINED_REGISTERS

project = angr.Project("11011001", auto_load_libs=False)

state = project.factory.call_state(0x400CB0)
state.options.add(ZERO_FILL_UNCONSTRAINED_REGISTERS)

simgr = project.factory.simulation_manager(state)

flag = claripy.BVS('flag', 32 *20)
inputstate = flag.chop(32)
# for i in range(20):
#     it = claripy.BVS(f'i_{i}', 32)
#     inputstate.append(it)
#     itc = (it& 0xFFF00000) == 0
#     print(itc)
#     state.solver.add(itc)

# @project.hook(0x400F4D , length=0x400F5E - 0x400F4D)
# def nop(state):
#     pass
globalbreakpoint = 0x400e92
def trace(state):
    cmp = state.regs.rip == 0x400D5D
    # breakpoint = state.regs.rip == globalbreakpoint
    print('============= rip:', state.regs.rip, ' ==============')
    # print('      rax:', state.regs.rax)
    # print('      rsp:', state.regs.rsp)
    # print('      rbp:', state.regs.rbp)
    # print('      rbx:', state.regs.rbx)
    # print('      r14:', state.regs.r14)
    # print('      constratints ', state.solver.constraints)
    # if breakpoint.is_true():
    #     IPython.embed()
    return cmp.is_true()

@project.hook(0x400D08, length=0x400D1C - 0x400D08)
def skip_input(state):
    
    rbp =  state.solver.eval(state.regs.rbp)
    rsp =  state.solver.eval(state.regs.rsp)
    
    
    print(f"[i] skip input {hex(rbp)} {hex(rsp)} {hex(state.solver.eval(state.regs.rbx))} {hex(state.solver.eval(state.regs.r14))}")
    for i in range(20):
        state.memory.store(rbp, inputstate[i])
        rbp += 4
    state.regs.rbx = state.regs.r14
    print(f"[i] skip input {hex(rbp)} {hex(rsp)} {hex(state.solver.eval(state.regs.rbx))} {hex(state.solver.eval(state.regs.r14))}")
    trace(state)
    
def ___popcountdi2(state):
    toscan = state.regs.rdi
    cnt = claripy.BVV(0, 64)
    for i in range(64):
        mask = claripy.BVV(1 << i, 64)
        masked = toscan & mask
        bit = masked >> i
        cnt += bit
    
    print('___popcountdi2 =>', cnt)
    state.regs.rax = cnt


@project.hook(0x400E8D , length=0x400E92 - 0x400E8D )
def ___popcountdi2_1(state):
    ___popcountdi2(state)

@project.hook(0x400E57  , length=0x400E5C - 0x400E57  )
def ___popcountdi2_2(state):
    ___popcountdi2(state)
    

res = simgr.explore(find=0x400F4D, avoid=trace)


def int_to_bytes(ii, nbytes):    
    return bytes.fromhex(hex(ii)[2:].rjust(nbytes*2, '0'))

sol = res.found[0]
bs = int_to_bytes(sol.eval(flag), 20*4)
print(bs)

print("Solution:")

for i in range(20):
    it = bs[i*4:i*4+4]
    jit = struct.unpack("I", it)[0]
    print(jit)


IPython.embed()
